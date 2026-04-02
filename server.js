const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
dotenv.config();

console.log("Key loaded:", process.env.GROQ_API_KEY ? "YES ✅" : "NO ❌");

const app = express();
app.use(cors());
app.use(express.json({ limit: '20mb' }));

app.get('/', (req, res) => {
    res.sendFile(__dirname + '/Index.html');
});

// Feature 1: Disposable Email Check
app.post('/check-email', async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email required' });

    const domain = email.split('@')[1]?.toLowerCase();
    if (!domain) return res.status(400).json({ error: 'Invalid email' });

    try {
        const response = await fetch('https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/disposable_email_blocklist.conf');
        const text = await response.text();
        const disposableDomains = new Set(text.split('\n').map(d => d.trim().toLowerCase()));

        const isDisposable = disposableDomains.has(domain);
        const freeProviders = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'rediffmail.com'];
        const isFreeProvider = freeProviders.includes(domain);

        res.json({
            email,
            domain,
            is_disposable: isDisposable,
            is_free_provider: isFreeProvider,
            risk: isDisposable ? 95 : isFreeProvider ? 40 : 0,
            verdict: isDisposable
                ? 'DISPOSABLE EMAIL — Instant scam signal!'
                : isFreeProvider
                ? 'Free email provider — MNCs never use Gmail to hire'
                : 'Legitimate business email domain'
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Feature 3: DNS/MX Record Check
app.post('/check-dns', async (req, res) => {
    const { domain } = req.body;
    if (!domain) return res.status(400).json({ error: 'Domain required' });

    try {
        const mxResponse = await fetch(`https://dns.google/resolve?name=${domain}&type=MX`);
        const mxData = await mxResponse.json();

        const spfResponse = await fetch(`https://dns.google/resolve?name=${domain}&type=TXT`);
        const spfData = await spfResponse.json();

        const hasMX = mxData.Answer && mxData.Answer.length > 0;
        const spfRecords = spfData.Answer || [];
        const hasSPF = spfRecords.some(r => r.data && r.data.includes('v=spf1'));

        let risk = 0;
        let verdict = '';
        let details = [];

        if (!hasMX) {
            risk += 60;
            details.push('No MX records found — domain cannot receive emails');
        } else {
            details.push(`MX records found — ${mxData.Answer.length} mail server(s) detected`);
        }

        if (!hasSPF) {
            risk += 30;
            details.push('No SPF record — email spoofing possible');
        } else {
            details.push('SPF record found — email authentication configured');
        }

        if (!hasMX && !hasSPF) {
            verdict = 'HIGH RISK — No email infrastructure. Likely a fake domain.';
        } else if (!hasSPF) {
            verdict = 'MODERATE RISK — No SPF record. Emails from this domain could be spoofed.';
        } else {
            verdict = 'Legitimate email infrastructure detected.';
        }

        res.json({ domain, has_mx: hasMX, has_spf: hasSPF, risk, verdict, details });

    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Feature 4: Domain Age Check via crt.sh
app.post('/check-domain-age', async (req, res) => {
    const { domain } = req.body;
    if (!domain) return res.status(400).json({ error: 'Domain required' });

    try {
        const response = await fetch(`https://crt.sh/?q=${domain}&output=json`);
        const certs = await response.json();

        if (!certs || certs.length === 0) {
            return res.json({
                domain,
                risk: 50,
                verdict: 'No SSL certificate history found — domain may be very new or fake.',
                first_seen: null,
                days_old: null
            });
        }

        const dates = certs.map(c => new Date(c.not_before)).filter(d => !isNaN(d));
        const earliest = new Date(Math.min(...dates));
        const daysOld = Math.floor((new Date() - earliest) / (1000 * 60 * 60 * 24));

        let risk = 0;
        let verdict = '';

        if (daysOld < 30) {
            risk = 90;
            verdict = `VERY HIGH RISK — Domain is only ${daysOld} days old. Newly created domains are a major scam signal.`;
        } else if (daysOld < 180) {
            risk = 50;
            verdict = `MODERATE RISK — Domain is ${daysOld} days old. Verify carefully.`;
        } else if (daysOld < 365) {
            risk = 20;
            verdict = `Low risk — Domain is ${daysOld} days old.`;
        } else {
            risk = 0;
            verdict = `Domain is ${Math.floor(daysOld / 365)} year(s) old. Established and trustworthy.`;
        }

        res.json({ domain, risk, verdict, first_seen: earliest.toISOString().split('T')[0], days_old: daysOld });

    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Feature 5: Reverse IP Check via HackerTarget
app.post('/check-reverse-ip', async (req, res) => {
    const { domain } = req.body;
    if (!domain) return res.status(400).json({ error: 'Domain required' });

    try {
        const response = await fetch(`https://api.hackertarget.com/reverseiplookup/?q=${domain}`);
        const text = await response.text();

        if (text.includes('error') || text.includes('API count exceeded')) {
            return res.json({
                domain,
                risk: 0,
                verdict: 'Reverse IP check unavailable at this time.',
                neighbor_count: null,
                neighbors: []
            });
        }

        const neighbors = text.trim().split('\n').map(s => s.trim()).filter(Boolean);
        const neighborCount = neighbors.length;
        const riskyKeywords = ['adult', 'casino', 'gambling', 'porn', 'xxx', 'bet', 'loan', 'spam', 'fake'];
        const riskyNeighbors = neighbors.filter(n => riskyKeywords.some(kw => n.toLowerCase().includes(kw)));

        let risk = 0;
        let verdict = '';

        if (riskyNeighbors.length > 0) {
            risk = 80;
            verdict = `HIGH RISK — Server hosts suspicious sites: ${riskyNeighbors.slice(0, 3).join(', ')}`;
        } else if (neighborCount > 100) {
            risk = 40;
            verdict = `MODERATE RISK — Server hosts ${neighborCount} sites. Cheap shared hosting often used by scammers.`;
        } else if (neighborCount > 0) {
            risk = 10;
            verdict = `Server hosts ${neighborCount} site(s). No suspicious neighbors detected.`;
        } else {
            risk = 0;
            verdict = 'Dedicated server detected. Low risk.';
        }

        res.json({ domain, risk, verdict, neighbor_count: neighborCount, neighbors: neighbors.slice(0, 5) });

    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Groq AI Analyze Route
app.post('/analyze', async (req, res) => {
    const { messages, model } = req.body;
    console.log("Request received — model:", model);

    if (!process.env.GROQ_API_KEY) {
        return res.status(500).json({ error: 'API key not configured on server.' });
    }

    try {
        const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${process.env.GROQ_API_KEY}`
            },
            body: JSON.stringify({ model, messages, temperature: 0.3, max_tokens: 1024 })
        });

        const data = await response.json();

        if (data.error) {
            console.error("Groq API error:", data.error);
            return res.status(400).json({ error: data.error.message || 'Groq API error' });
        }

        console.log("Groq response OK:", JSON.stringify(data).substring(0, 100));
        res.json(data);

    } catch (err) {
        console.error("Server error:", err.message);
        res.status(500).json({ error: err.message });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`TrustJobAI Server running on port ${PORT}`);
});
