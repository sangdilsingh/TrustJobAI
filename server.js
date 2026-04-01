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

// Disposable Email Check Route
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
                ? '🚨 DISPOSABLE EMAIL — Instant scam signal!'
                : isFreeProvider
                ? '⚠️ Free email provider — MNCs never use Gmail to hire'
                : '✅ Legitimate business email domain'
        });

    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

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
