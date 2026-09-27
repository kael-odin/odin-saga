import { createInstallationToken, getInstallationId, signAppJwt } from './github-client'
import { GITHUB_CONFIG } from '@/consts'
import { useAuthStore } from '@/hooks/use-auth'
import { toast } from 'sonner'
import { decrypt,encrypt } from './aes256-util'

const GITHUB_TOKEN_CACHE_KEY = 'github_token'
const GITHUB_PEM_CACHE_KEY = 'p_info'

function getTokenFromCache(): string | null {
	if (typeof sessionStorage === 'undefined') return null
	try {
		return sessionStorage.getItem(GITHUB_TOKEN_CACHE_KEY)
	} catch {
		return null
	}
}

function saveTokenToCache(token: string): void {
	if (typeof sessionStorage === 'undefined') return
	try {
		sessionStorage.setItem(GITHUB_TOKEN_CACHE_KEY, token)
	} catch (error) {
		console.error('Failed to save token to cache:', error)
	}
}

function clearTokenCache(): void {
	if (typeof sessionStorage === 'undefined') return
	try {
		sessionStorage.removeItem(GITHUB_TOKEN_CACHE_KEY)
	} catch (error) {
		console.error('Failed to clear token cache:', error)
	}
}

export async function getPemFromCache(): Promise<string | null> {
	if (typeof sessionStorage === 'undefined') return null
	try {
		// 解密缓存中的 pem
		const encryptedPem = sessionStorage.getItem(GITHUB_PEM_CACHE_KEY)
		if (!encryptedPem) return null
		return await decrypt(encryptedPem, GITHUB_CONFIG.ENCRYPT_KEY)
	} catch {
		return null
	}
}

export async function savePemToCache(pem: string): Promise<void> {
	if (typeof sessionStorage === 'undefined') return
	// 安全底线：ENCRYPT_KEY 未配置（或仍是占位）时不落盘——
	// 前端 bundle 里的固定密钥只能混淆，挡不住 XSS 窃取
	const key = GITHUB_CONFIG.ENCRYPT_KEY
	if (!key) {
		toast.warning('未配置加密密钥（NEXT_PUBLIC_GITHUB_ENCRYPT_KEY），本次不缓存私钥')
		return
	}
	try {
		const encryptedPem = await encrypt(pem, key)
		sessionStorage.setItem(GITHUB_PEM_CACHE_KEY, encryptedPem)
	} catch (error) {
		console.error('Failed to save pem to cache:', error)
	}
}

function clearPemCache(): void {
	if (typeof sessionStorage === 'undefined') return
	try {
		sessionStorage.removeItem(GITHUB_PEM_CACHE_KEY)
	} catch (error) {
		console.error('Failed to clear pem cache:', error)
	}
}

export function clearAllAuthCache(): void {
	clearTokenCache()
	clearPemCache()
}

export async function hasAuth(): Promise<boolean> {
	return !!getTokenFromCache() || !!(await getPemFromCache())
}

/**
 * 统一的认证 Token 获取
 * 优先走服务端签发（/api/github/token，私钥只存在服务端环境变量里）；
 * 服务端未配置（503）时回退到旧的本地 PEM 流程。
 * @returns GitHub Installation Token
 */
export async function getAuthToken(): Promise<string> {
	// 1. 先尝试从缓存获取 token
	const cachedToken = getTokenFromCache()
	if (cachedToken) {
		toast.info('使用缓存的令牌...')
		return cachedToken
	}

	// 2. 服务端签发模式：PEM 不经过浏览器
	try {
		const res = await fetch('/api/github/token', { method: 'POST' })
		if (res.ok) {
			const { token } = (await res.json()) as { token: string }
			if (token) {
				toast.success('已通过服务端获取安装令牌')
				saveTokenToCache(token)
				return token
			}
		}
		if (res.status !== 503) {
			console.error('[auth] server token issue failed:', res.status)
		}
		// 503 = 服务端未配置凭据，走回退
	} catch (err) {
		console.warn('[auth] server token endpoint unreachable, falling back to local PEM:', err)
	}

	// 3. 回退：获取私钥（从缓存）
	const privateKey = useAuthStore.getState().privateKey
	if (!privateKey) {
		throw new Error('需要先设置私钥。请使用 useAuth().setPrivateKey()，或在服务端配置 GITHUB_APP_PRIVATE_KEY')
	}

	toast.info('正在签发 JWT...')
	const jwt = signAppJwt(GITHUB_CONFIG.APP_ID, privateKey)

	toast.info('正在获取安装信息...')
	const installationId = await getInstallationId(jwt, GITHUB_CONFIG.OWNER, GITHUB_CONFIG.REPO)

	toast.info('正在创建安装令牌...')
	const token = await createInstallationToken(jwt, installationId)

	saveTokenToCache(token)

	return token
}
