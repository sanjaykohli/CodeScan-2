// const { GoogleGenerativeAI } = require("@google/generative-ai");

// const genAI = new GoogleGenerativeAI("API_Key");
// const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash" });

// export default async function handler(req, res) {
//   if (req.method === "POST") {
//     const { prompt } = req.body;

//     try {
//       const result = await model.generateContent(prompt);

//       // Validate response
//       if (result && result.response && result.response.text) {
//         const solutions = result.response.text.split("\n").filter(Boolean); // Splitting lines into solutions
//         res.status(200).json({ solutions });
//       } else {
//         res.status(500).json({ error: "No response text generated" });
//       }
//     } catch (error) {
//       console.error("Gemini API Error:", error.message || error);
//       res.status(500).json({ error: "Error generating solutions" });
//     }
//   } else {
//     res.status(405).json({ error: "Method not allowed" });
//   }
// }
