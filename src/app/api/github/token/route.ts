import { NextRequest, NextResponse } from 'next/server'
import { getInstallToken, hasWriteCredential } from '@/lib/likes-store'

export const dynamic = 'force-dynamic'

/**
 * 服务端签发 GitHub 安装令牌：私钥只放在服务端环境变量
 * （GITHUB_APP_PRIVATE_KEY / GITHUB_TOKEN），浏览器从此不再持有/缓存
 * PEM。需要跨仓库操作（评论、点赞等）时客户端 POST 这里拿短时 token。
 *
 * 环境变量未配置时返回 503，客户端自动回退到旧的本地私钥流程。
 */
export async function POST(req: NextRequest) {
	if (!hasWriteCredential()) {
		return NextResponse.json({ reason: 'not_configured' }, { status: 503 })
	}
	const origin = req.headers.get('origin')
	if (origin) {
		try {
			if (new URL(origin).host !== req.headers.get('host')) {
				return NextResponse.json({ error: 'cross-site rejected' }, { status: 403 })
			}
		} catch {
			return NextResponse.json({ error: 'bad origin' }, { status: 403 })
		}
	}
	try {
		const token = await getInstallToken()
		return NextResponse.json({ token })
	} catch (err) {
		console.error('[api/github/token] failed:', err)
		return NextResponse.json({ error: 'token issue failed' }, { status: 502 })
	}
}
