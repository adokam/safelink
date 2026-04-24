// /api/analyze.js
// Vercel Edge/Serverless Function
// Calls Claude API (with web_search tool) + Google Safe Browsing

export default async function handler(req, res) {
  // CORS headers (adjust origin in production to your domain)
  res.setHeader('Access-Control-Allow-Origin', process.env.ALLOWED_ORIGIN || '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const { input, type } = req.body;

  if (!input || typeof input !== 'string' || input.length > 500) {
    return res.status(400).json({ error: 'Invalid input' });
  }

  // ── 1. Google Safe Browsing check ──────────────────────────────────────────
  let gsbResult = null;
  const urlMatch = input.match(/https?:\/\/[^\s]+|(?:www\.)?[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:\/[^\s]*)?/);

  if (urlMatch && process.env.GOOGLE_SAFE_BROWSING_API_KEY) {
    const rawUrl = urlMatch[0];
    const targetUrl = rawUrl.startsWith('http') ? rawUrl : `https://${rawUrl}`;

    try {
      const gsbRes = await fetch(
        `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${process.env.GOOGLE_SAFE_BROWSING_API_KEY}`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            client: { clientId: 'safelink-ai', clientVersion: '1.0.0' },
            threatInfo: {
              threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
              platformTypes: ['ANY_PLATFORM'],
              threatEntryTypes: ['URL'],
              threatEntries: [{ url: targetUrl }]
            }
          })
        }
      );

      const gsbData = await gsbRes.json();
      const matches = gsbData.matches || [];

      gsbResult = {
        flagged: matches.length > 0,
        threats: matches.map(m => m.threatType),
        url: targetUrl
      };
    } catch (e) {
      console.error('GSB error:', e.message);
    }
  }

  // ── 2. Claude AI analysis with web search ──────────────────────────────────
  const systemPrompt = `You are SafeLink AI, a professional cybersecurity and fraud analyst specializing in identifying scam websites, fake investment platforms, and fraudulent apps — especially targeting users in Nigeria and West Africa.

The user has submitted a site/app for a "${type}" safety check.

Your job:
1. Use the web_search tool to search for information about this site/app — look for scam reports, reviews, registration info, complaints, and news.
2. Analyze ALL available signals: domain patterns, promises made, regulatory status, user complaints, transparency, etc.
3. Return ONLY a valid JSON object. No markdown. No explanation outside JSON.

JSON format:
{
  "verdict": "SAFE" | "WARNING" | "DANGER",
  "verdict_label": "Short phrase e.g. 'Likely Scam', 'Verified Platform', 'Proceed With Caution'",
  "summary": "2-3 sentence plain English summary of your overall finding",
  "scores": [
    {"label": "Trust Score", "value": 0-100},
    {"label": "Transparency", "value": 0-100},
    {"label": "Red Flags", "value": 0-100},
    {"label": "Regulation", "value": 0-100}
  ],
  "findings": [
    {"icon": "emoji", "title": "Finding title", "detail": "Detailed explanation"},
    {"icon": "emoji", "title": "...", "detail": "..."},
    {"icon": "emoji", "title": "...", "detail": "..."},
    {"icon": "emoji", "title": "...", "detail": "..."},
    {"icon": "emoji", "title": "...", "detail": "..."}
  ],
  "recommendation": "Clear, direct, actionable advice to the user. Be specific.",
  "agenda": {
    "summary": "One sentence: what this site is really after e.g. 'This site is trying to steal your money and personal data'",
    "motives": [
      {
        "icon": "emoji",
        "title": "Motive name e.g. 'Stealing Your Money'",
        "description": "Plain explanation of HOW they are trying to do this and WHY. Be specific and direct. Talk to the user like a smart friend warning them.",
        "level": "high" | "medium" | "low"
      }
    ]
  }
}

Red Flags score: 100 = zero red flags found, 0 = extreme red flags everywhere.

Be rigorous. Common scam signals: .top/.xyz/.club domains registered recently, no company registration, promises of guaranteed returns, crypto-only payments, no physical address, fake testimonials, unlicensed financial activity, pressure tactics, no working customer support, complaints on Nairaland/Reddit/ScamAdviser.`;

  try {
    const claudeRes = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.CLAUDE_API_KEY,
        'anthropic-version': '2023-06-01',
        'anthropic-beta': 'tools-2024-04-04'
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-20250514',
        max_tokens: 1500,
        system: systemPrompt,
        tools: [
          {
            type: 'web_search_20250305',
            name: 'web_search'
          }
        ],
        messages: [
          {
            role: 'user',
            content: `Analyze this for safety: ${input}`
          }
        ]
      })
    });

    if (!claudeRes.ok) {
      const errBody = await claudeRes.text();
      throw new Error(`Claude API error ${claudeRes.status}: ${errBody}`);
    }

    const claudeData = await claudeRes.json();

    // Extract the final text block (after tool use)
    const textBlock = claudeData.content
      ?.filter(b => b.type === 'text')
      ?.map(b => b.text)
      ?.join('') || '';

    // Parse JSON — strip any accidental markdown fences
    const clean = textBlock.replace(/```json|```/gi, '').trim();
    const analysis = JSON.parse(clean);

    return res.status(200).json({ analysis, gsb: gsbResult });

  } catch (err) {
    console.error('Analysis error:', err);
    return res.status(500).json({ error: err.message || 'Analysis failed' });
  }
}
