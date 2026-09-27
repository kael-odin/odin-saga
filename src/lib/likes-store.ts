import crypto from 'node:crypto'
import path from 'node:path'
import fs from 'node:fs/promises'
import { GITHUB_CONFIG } from '@/consts'

/**
 * 点赞计数后端（服务端专用，勿在客户端引入）。
 * 数据存储在仓库根目录的 likes.json，通过 GitHub Contents API 读改写，
 * 授权优先使用环境变量 GITHUB_APP_PRIVATE_KEY（GitHub App 私钥，签 JWT 换安装令牌），
 * 其次使用 GITHUB_TOKEN（细粒度 PAT，需本仓库 Contents 读写权限）。
 */

const FILE_PATH = 'likes.json'
const RAW_URL = `https://raw.githubusercontent.com/${GITHUB_CONFIG.OWNER}/${GITHUB_CONFIG.REPO}/${GITHUB_CONFIG.BRANCH}/${FILE_PATH}`
const GH_API = 'https://api.github.com'
const GH_HEADERS = {
	Accept: 'application/vnd.github+json',
	'X-GitHub-Api-Version': '2022-11-28'
}

export function hasWriteCredential(): boolean {
	return Boolean(process.env.GITHUB_APP_PRIVATE_KEY || process.env.GITHUB_TOKEN)
}

export function sanitizeSlug(raw: string | null | undefined): string {
	return (raw || '').replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 64)
}

function signAppJwt(appId: string, privateKeyPem: string): string {
	const now = Math.floor(Date.now() / 1000)
	const encode = (obj: object) => Buffer.from(JSON.stringify(obj)).toString('base64url')
	const pem = privateKeyPem.includes('\\n') ? privateKeyPem.replace(/\\n/g, '\n') : privateKeyPem
	const input = `${encode({ alg: 'RS256', typ: 'JWT' })}.${encode({ iat: now - 60, exp: now + 480, iss: appId })}`
	const signature = crypto.createSign('RSA-SHA256').update(input).sign(pem, 'base64url')
	return `${input}.${signature}`
}

export async function getInstallToken(): Promise<string> {
	const appId = process.env.NEXT_PUBLIC_GITHUB_APP_ID || '-'
	const pem = process.env.GITHUB_APP_PRIVATE_KEY
	if (!pem) throw new Error('missing credential')

	const jwt = signAppJwt(appId, pem)
	const installationRes = await fetch(`${GH_API}/repos/${GITHUB_CONFIG.OWNER}/${GITHUB_CONFIG.REPO}/installation`, {
		headers: { ...GH_HEADERS, Authorization: `Bearer ${jwt}` }
	})
	if (!installationRes.ok) throw new Error(`installation lookup failed: ${installationRes.status}`)
	const { id } = (await installationRes.json()) as { id: number }

	const tokenRes = await fetch(`${GH_API}/app/installations/${id}/access_tokens`, {
		method: 'POST',
		headers: { ...GH_HEADERS, Authorization: `Bearer ${jwt}` }
	})
	if (!tokenRes.ok) throw new Error(`create installation token failed: ${tokenRes.status}`)
	const { token } = (await tokenRes.json()) as { token: string }
	return token
}

async function getCredential(): Promise<string> {
	if (process.env.GITHUB_TOKEN) return process.env.GITHUB_TOKEN
	return getInstallToken()
}

// Installation token 有效期 1 小时，内存缓存避免每次读数都签 JWT
let cachedToken: { token: string; expiresAt: number } | null = null

async function getCredentialCached(): Promise<string | null> {
	try {
		if (process.env.GITHUB_TOKEN) return process.env.GITHUB_TOKEN
		if (cachedToken && Date.now() < cachedToken.expiresAt) return cachedToken.token
		const token = await getInstallToken()
		cachedToken = { token, expiresAt: Date.now() + 45 * 60 * 1000 }
		return token
	} catch {
		return null
	}
}

type LikesMap = Record<string, number>

/** Contents API 读取：附带文件 sha，供 PUT 乐观锁使用（raw 回退无 sha） */
async function readLikesWithSha(): Promise<{ likes: LikesMap; sha?: string }> {
	const credential = await getCredentialCached()
	if (credential) {
		const res = await fetch(`${GH_API}/repos/${GITHUB_CONFIG.OWNER}/${GITHUB_CONFIG.REPO}/contents/${FILE_PATH}`, {
			headers: { ...GH_HEADERS, Authorization: `Bearer ${credential}` },
			cache: 'no-store'
		})
		if (res.ok) {
			const data = (await res.json()) as { content?: string; sha?: string }
			return {
				likes: JSON.parse(Buffer.from(data.content ?? '', 'base64').toString('utf-8')) as LikesMap,
				sha: data.sha
			}
		}
		if (res.status !== 404) throw new Error(`read likes failed: ${res.status}`)
		return { likes: {} }
	}
	const res = await fetch(RAW_URL, { cache: 'no-store' })
	if (res.status === 404) return { likes: {} }
	if (!res.ok) throw new Error(`read likes failed: ${res.status}`)
	return { likes: (await res.json()) as LikesMap }
}

async function readLikesFromGithub(): Promise<LikesMap> {
	// 优先走 Contents API：无 CDN 缓存，写入后立即可读；无凭据时回退 raw（约 5 分钟 CDN 延迟）
	const credential = await getCredentialCached()
	if (credential) {
		const res = await fetch(`${GH_API}/repos/${GITHUB_CONFIG.OWNER}/${GITHUB_CONFIG.REPO}/contents/${FILE_PATH}`, {
			headers: { ...GH_HEADERS, Authorization: `Bearer ${credential}` },
			cache: 'no-store'
		})
		if (res.ok) {
			const data = (await res.json()) as { content?: string }
			return JSON.parse(Buffer.from(data.content ?? '', 'base64').toString('utf-8')) as LikesMap
		}
		if (res.status !== 404) throw new Error(`read likes failed: ${res.status}`)
		return {}
	}

	const res = await fetch(RAW_URL, { cache: 'no-store' })
	if (res.status === 404) return {}
	if (!res.ok) throw new Error(`read likes failed: ${res.status}`)
	return (await res.json()) as LikesMap
}

export async function readLikes(): Promise<LikesMap> {
	try {
		return await readLikesFromGithub()
	} catch {
		// 回退到构建时打包进部署的文件（raw 有分钟级缓存或首次未推送时）
		try {
			const local = await fs.readFile(path.join(process.cwd(), FILE_PATH), 'utf-8')
			return JSON.parse(local) as LikesMap
		} catch {
			return {}
		}
	}
}

/**
 * 用「读取时拿到的同一个 sha」做 PUT（GitHub 乐观锁）：并发写入时后到者
 * 会收到 409 而不是静默覆盖。之前先读数再重新取 sha 的写法让乐观锁失效，
 * 并发点赞会互相覆盖丢计数。
 */
async function writeLikes(likes: LikesMap, message: string, sha?: string): Promise<void> {
	const token = await getCredential()
	const headers = { ...GH_HEADERS, Authorization: `Bearer ${token}` }

	const putRes = await fetch(`${GH_API}/repos/${GITHUB_CONFIG.OWNER}/${GITHUB_CONFIG.REPO}/contents/${FILE_PATH}`, {
		method: 'PUT',
		headers,
		body: JSON.stringify({
			message,
			content: Buffer.from(JSON.stringify(likes, null, '\t') + '\n', 'utf-8').toString('base64'),
			...(sha ? { sha } : {})
		})
	})
	if (!putRes.ok) throw new Error(`write likes failed: ${putRes.status}`)
}

/**
 * 读-改-写某个 slug 的计数。带读取时 sha 做 CAS，409/422 冲突时
 * 整体重读重算，最多 5 轮；仍失败则抛错让调用方返回 500（客户端可重试）。
 */
export async function incrementLike(slug: string, delta: number): Promise<number> {
	let lastErr: unknown = new Error('increment failed')
	for (let attempt = 0; attempt < 5; attempt++) {
		const { likes, sha } = await readLikesWithSha().catch(() => ({ likes: {} as LikesMap, sha: undefined as string | undefined }))
		const next = (likes[slug] ?? 0) + delta
		try {
			await writeLikes({ ...likes, [slug]: Math.max(0, next) }, `❤️ like: ${slug} ${delta > 0 ? '+1' : delta}`, sha)
			return Math.max(0, next)
		} catch (err) {
			lastErr = err
			const status = Number((err as Error)?.message?.match(/(\d{3})$/)?.[1] ?? 0)
			if (status !== 409 && status !== 422) throw err
		}
	}
	throw lastErr
}
