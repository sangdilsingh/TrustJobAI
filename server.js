const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');

dotenv.config();
console.log("Key loaded:", process.env.GROQ_API_KEY ? "YES ✅" : "NO ❌");

const app = express();
app.use(cors());
app.use(express.json());

app.get('/', (req, res) => {
    res.sendFile(__dirname + '/Index.html');
});

app.post('/analyze', async (req, res) => {
    const { messages, model } = req.body;
    console.log("Request received — model:", model);
    try {
        const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${process.env.GROQ_API_KEY}`
            },
            body: JSON.stringify({ model, messages, temperature: 0.3 })
        });
        const data = await response.json();
        console.log("Groq response:", JSON.stringify(data).substring(0, 100));
        res.json(data);
   } catch (err) {
    console.error("Full error:", JSON.stringify(err));
    console.error("Error message:", err.message);
    res.status(500).json({ error: err.message });
}
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`TrustJobAI Server running on port ${PORT}`);
});
