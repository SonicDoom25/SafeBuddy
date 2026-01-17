const express = require('express');
const bodyParser = require('body-parser');
const axios = require('axios');
const path = require('path');

const app = express();
const PORT = 3000;

// 🔐 API key
const API_KEY = process.env.SAFEBUDDY_API_KEY;

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Serve static files (CSS, JS, images, HTML)
app.use(express.static(path.join(__dirname)));

// ✅ Serve homepage
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'home_page.html'));
});

// ✅ Fix refresh / back button issue on POST route
app.get('/check-url', (req, res) => {
  res.redirect('/');
});


// ✅ URL safety check endpoint
app.post('/check-url', async (req, res) => {
  const { url } = req.body;

  try {
    const response = await axios.post(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${API_KEY}`,
      {
        client: {
          clientId: "safe-buddy",
          clientVersion: "1.0"
        },
        threatInfo: {
          threatTypes: [
            "MALWARE",
            "SOCIAL_ENGINEERING",
            "UNWANTED_SOFTWARE",
            "POTENTIALLY_HARMFUL_APPLICATION"
          ],
          platformTypes: ["ANY_PLATFORM"],
          threatEntryTypes: ["URL"],
          threatEntries: [{ url }]
        }
      }
    );

    // 🔴 If threats are found → REDIRECT (IMPORTANT)
    if (response.data?.matches?.length) {
      const threats = response.data.matches.map(m => m.threatType);
      console.log("⚠️ Threats detected:", threats);

      return res.redirect(
        `/unsafe.html?threats=${encodeURIComponent(threats.join(','))}`
      );
    }

    // 🟢 If no threats → REDIRECT (NOT sendFile)
    console.log("✅ No threats detected");
    return res.redirect('/safe.html');

  } catch (error) {
    console.error("❌ Safe Browsing error:", error.response?.data || error.message);
    res.status(500).send("Error checking URL safety.");
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`✅ SafeBuddy backend running at http://localhost:${PORT}`);

});
