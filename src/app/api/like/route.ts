import { NextRequest, NextResponse } from 'next/server'
import { hasWriteCredential, incrementLike, readLikes, sanitizeSlug } from '@/lib/likes-store'

export const dynamic = 'force-dynamic'

/** 同一 IP 对同一 slug 的点赞间隔：24 小时 */
const LIKE_INTERVAL_MS = 24 * 60 * 60 * 1000
const hits = new Map<string, number>()

function isRateLimited(key: string): boolean {
	const now = Date.now()
	// 简单清理，防止 Map 无限增长
	if (hits.size > 10000) {
		for (const [k, t] of hits) {
			if (now - t > LIKE_INTERVAL_MS) hits.delete(k)
		}
	}
	const last = hits.get(key)
	if (last && now - last < LIKE_INTERVAL_MS) return true
	hits.set(key, now)
	return false
}

function clientIp(req: NextRequest): string {
	// Vercel/Cloudflare 都会把真实 IP 追加在 x-forwarded-for 末段（首段客户端可伪造）；
	// 优先使用平台专属头
	return (
		req.headers.get('x-real-ip')?.trim() ||
		req.headers.get('cf-connecting-ip')?.trim() ||
		req.headers.get('x-forwarded-for')?.split(',').pop()?.trim() ||
		'unknown'
	)
}

/** 跨站请求拒绝：第三方页面可以让访客在不知情下刷赞（配合限流会被放大） */
function isCrossSite(req: NextRequest): boolean {
	const origin = req.headers.get('origin')
	if (!origin) return false
	try {
		return new URL(origin).host !== req.headers.get('host')
	} catch {
		return true
	}
}

export async function GET(req: NextRequest) {
	const slug = sanitizeSlug(req.nextUrl.searchParams.get('slug'))
	if (!slug) return NextResponse.json({ error: 'invalid slug' }, { status: 400 })

	const likes = await readLikes()
	return NextResponse.json({ count: likes[slug] ?? 0 })
}

export async function POST(req: NextRequest) {
	const slug = sanitizeSlug(req.nextUrl.searchParams.get('slug'))
	if (!slug) return NextResponse.json({ error: 'invalid slug' }, { status: 400 })

	if (isCrossSite(req)) {
		return NextResponse.json({ error: 'cross-site like rejected' }, { status: 403 })
	}

	if (!hasWriteCredential()) {
		return NextResponse.json({ reason: 'not_configured', error: 'server missing GITHUB_APP_PRIVATE_KEY / GITHUB_TOKEN' }, { status: 503 })
	}

	if (isRateLimited(`${clientIp(req)}:${slug}`)) {
		return NextResponse.json({ reason: 'rate_limited' }, { status: 429 })
	}

	try {
		const count = await incrementLike(slug, 1)
		return NextResponse.json({ count })
	} catch (err) {
		console.error('[api/like] write failed:', err)
		return NextResponse.json({ error: 'write failed' }, { status: 500 })
	}
}
