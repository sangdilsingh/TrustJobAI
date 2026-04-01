// Disposable Email Check Route
app.post('/check-email', async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email required' });

    const domain = email.split('@')[1]?.toLowerCase();
    if (!domain) return res.status(400).json({ error: 'Invalid email' });

    try {
        // Free disposable email list from GitHub
        const response = await fetch('https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/disposable_email_blocklist.conf');
        const text = await response.text();
        const disposableDomains = new Set(text.split('\n').map(d => d.trim().toLowerCase()));

        const isDisposable = disposableDomains.has(domain);

        // MNC Gmail check
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
