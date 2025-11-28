import { GoogleGenerativeAI } from "@google/generative-ai";

class ResumeJDAnalyzer {
  constructor(apiKey) {
    this.genAI = new GoogleGenerativeAI(apiKey);
    this.model = this.genAI.getGenerativeModel({
      model: "gemini-2.5-flash",
      generationConfig: {
        temperature: 0.1, // Reduced for more consistent output
        topP: 0.8,
        topK: 30,
        maxOutputTokens: 5096, // Reduced to prevent truncation
        responseMimeType: "application/json",
      },
    });
  }

  /**
   * Analyzes resume against job description
   * @param {string} jobDescription - The job description text
   * @param {string} resume - The resume text
   * @returns {Promise<Object>} Analysis results with similarity score and skills breakdown
   */
  async analyzeResumeMatch(jobDescription, resume) {
    // Truncate inputs if they're too long to prevent token overflow
    const maxInputLength = 8000; // Conservative limit
    const truncatedJD =
      jobDescription.length > maxInputLength
        ? jobDescription.substring(0, maxInputLength) + "..."
        : jobDescription;
    const truncatedResume =
      resume.length > maxInputLength
        ? resume.substring(0, maxInputLength) + "..."
        : resume;

    const prompt = this.createAnalysisPrompt(truncatedJD, truncatedResume);

    try {
      const result = await this.model.generateContent(prompt);
      const response = await result.response;
      const analysisText = response.text();

      // Clean and parse JSON response with multiple attempts
      const analysis = this.parseJsonResponse(analysisText);

      // Validate and enhance the response
      return this.validateAndEnhanceResponse(analysis);
    } catch (error) {
      console.error("Analysis error details:", error);

      // Fallback to simpler analysis if main analysis fails
      try {
        console.log("Attempting fallback analysis...");
        return await this.fallbackAnalysis(truncatedJD, truncatedResume);
      } catch (fallbackError) {
        console.error("Fallback analysis also failed:", fallbackError);
        throw new Error(`Analysis failed: ${error.message}`);
      }
    }
  }

  /**
   * Fallback analysis with simpler prompt when main analysis fails
   */
  async fallbackAnalysis(jobDescription, resume) {
    const simplePrompt = `Analyze this resume against the job description and return ONLY valid JSON:

Job Description: ${jobDescription.substring(0, 2000)}

Resume: ${resume.substring(0, 2000)}

Return exactly this JSON structure with no additional text:
{
  "overall_similarity_score": 75,
  "matching_strengths": {
    "hard_skills": ["skill1", "skill2"],
    "soft_skills": ["communication", "teamwork"],
    "experience_areas": ["relevant experience"],
    "qualifications": ["relevant qualifications"],
    "achievements": ["notable achievements"]
  },
  "missing_critical_elements": {
    "hard_skills": ["missing skill1"],
    "soft_skills": ["missing soft skill"],
    "experience_gaps": ["missing experience"],
    "qualifications": ["missing qualification"],
    "other_requirements": ["other missing items"]
  },
  "recommendations": {
    "for_candidate": ["improve skill X"],
    "for_recruiter": ["focus on Y during interview"],
  }
}`;

    try {
      const result = await this.model.generateContent(simplePrompt);
      const response = await result.response;
      const analysisText = response.text();

      const analysis = this.parseJsonResponse(analysisText);
      return this.validateAndEnhanceSimpleResponse(analysis);
    } catch (error) {
      // Return a basic structure if even fallback fails
      return this.getBasicAnalysisStructure();
    }
  }

  /**
   * Robust JSON parsing with multiple fallback strategies
   */
  parseJsonResponse(responseText) {
    console.log("Response length:", responseText.length);
    console.log("Response preview:", responseText.substring(0, 200));

    // Strategy 1: Direct JSON parsing
    try {
      const parsed = JSON.parse(responseText);
      console.log("✓ Direct JSON parsing successful");
      return parsed;
    } catch (e) {
      console.log("✗ Direct JSON parse failed:", e.message);
    }

    // Strategy 2: Extract JSON from markdown code blocks
    try {
      const jsonMatch = responseText.match(/```(?:json)?\s*([\s\S]*?)\s*```/i);
      if (jsonMatch) {
        const parsed = JSON.parse(jsonMatch[1]);
        console.log("✓ Markdown JSON extraction successful");
        return parsed;
      }
    } catch (e) {
      console.log("✗ Markdown JSON extraction failed:", e.message);
    }

    // Strategy 3: Find complete JSON object with brace counting
    try {
      const parsed = this.extractCompleteJson(responseText);
      if (parsed) {
        console.log("✓ Brace counting extraction successful");
        return parsed;
      }
    } catch (e) {
      console.log("✗ Brace counting extraction failed:", e.message);
    }

    // Strategy 4: Clean and fix common JSON issues
    try {
      const cleaned = this.cleanJsonString(responseText);
      const parsed = JSON.parse(cleaned);
      console.log("✓ JSON cleaning successful");
      return parsed;
    } catch (e) {
      console.log("✗ JSON cleaning failed:", e.message);
    }

    // Strategy 5: Attempt to fix truncated JSON
    try {
      const fixed = this.fixTruncatedJson(responseText);
      const parsed = JSON.parse(fixed);
      console.log("✓ Truncated JSON fix successful");
      return parsed;
    } catch (e) {
      console.log("✗ Truncated JSON fix failed:", e.message);
    }

    // Strategy 6: Extract partial JSON and fill missing fields
    try {
      const partial = this.extractPartialJson(responseText);
      if (partial) {
        console.log("✓ Partial JSON extraction successful");
        return partial;
      }
    } catch (e) {
      console.log("✗ Partial JSON extraction failed:", e.message);
    }

    console.error("All JSON parsing strategies failed");
    console.error("Response sample:", responseText.substring(0, 1000));
    throw new Error("Failed to parse AI response as JSON");
  }

  /**
   * Extract complete JSON object using brace counting
   */
  extractCompleteJson(text) {
    const startIndex = text.indexOf("{");
    if (startIndex === -1) return null;

    let braceCount = 0;
    let inString = false;
    let escapeNext = false;

    for (let i = startIndex; i < text.length; i++) {
      const char = text[i];

      if (escapeNext) {
        escapeNext = false;
        continue;
      }

      if (char === "\\") {
        escapeNext = true;
        continue;
      }

      if (char === '"' && !escapeNext) {
        inString = !inString;
        continue;
      }

      if (!inString) {
        if (char === "{") {
          braceCount++;
        } else if (char === "}") {
          braceCount--;
          if (braceCount === 0) {
            return JSON.parse(text.substring(startIndex, i + 1));
          }
        }
      }
    }
    return null;
  }

  /**
   * Clean common JSON formatting issues
   */
  cleanJsonString(text) {
    return text
      .replace(/```json\s*/g, "")
      .replace(/```/g, "")
      .replace(/,\s*([}\]])/g, "$1") // Remove trailing commas
      .replace(/[\r\n]+/g, " ") // Replace newlines with space
      .replace(/\\n/g, " ") // Unescaped newline characters
      .replace(/\s{2,}/g, " ") // Collapse extra spaces
      .trim();
  }

  /**
   * Fix truncated JSON by removing incomplete fields
   */
  fixTruncatedJson(text) {
    let startIndex = text.indexOf("{");
    if (startIndex === -1) return text;

    let braceCount = 0;
    let endIndex = -1;

    for (let i = startIndex; i < text.length; i++) {
      if (text[i] === "{") braceCount++;
      else if (text[i] === "}") braceCount--;

      if (braceCount === 0) {
        endIndex = i + 1;
        break;
      }
    }

    if (endIndex !== -1) {
      return text.slice(startIndex, endIndex);
    }

    // If closing brace not found, return best-effort fix
    return text.slice(startIndex) + "}".repeat(braceCount);
  }

  /**
   * Extract partial JSON and fill missing required fields
   */
  extractPartialJson(text) {
    try {
      // Try to extract whatever JSON we can get
      const startIndex = text.indexOf("{");
      if (startIndex === -1) return null;

      let partial = text.substring(startIndex);

      // Remove any text after the last }
      const lastBrace = partial.lastIndexOf("}");
      if (lastBrace !== -1) {
        partial = partial.substring(0, lastBrace + 1);
      }

      // Try to parse what we have
      let parsed;
      try {
        parsed = JSON.parse(partial);
      } catch (e) {
        // If parsing fails, try to create a minimal valid structure
        return this.getBasicAnalysisStructure();
      }

      // Fill in missing required fields
      return this.fillMissingFields(parsed);
    } catch (e) {
      return null;
    }
  }

  /**
   * Fill missing fields in partial JSON
   */
  fillMissingFields(partial) {
    const template = this.getBasicAnalysisStructure();

    // Recursively merge, keeping existing values
    function deepMerge(target, source) {
      for (const key in source) {
        if (
          source[key] &&
          typeof source[key] === "object" &&
          !Array.isArray(source[key])
        ) {
          target[key] = target[key] || {};
          deepMerge(target[key], source[key]);
        } else if (target[key] === undefined) {
          target[key] = source[key];
        }
      }
      return target;
    }

    return deepMerge(partial, template);
  }

  /**
   * Get basic analysis structure for fallback
   */
  getBasicAnalysisStructure() {
    return {
      overall_similarity_score: 50,
      matching_strengths: {
        hard_skills: ["Analysis incomplete - please retry"],
        soft_skills: ["Analysis incomplete - please retry"],
        experience_areas: ["Analysis incomplete - please retry"],
        qualifications: ["Analysis incomplete - please retry"],
        achievements: ["Analysis incomplete - please retry"],
      },
      missing_critical_elements: {
        hard_skills: ["Analysis incomplete - please retry"],
        soft_skills: ["Analysis incomplete - please retry"],
        experience_gaps: ["Analysis incomplete - please retry"],
        qualifications: ["Analysis incomplete - please retry"],
        other_requirements: ["Analysis incomplete - please retry"],
      },
      areas_for_improvement: [
        {
          category: "general",
          priority: "medium",
          description: "Analysis incomplete - please retry with shorter inputs",
          suggested_actions: ["Retry analysis", "Check input length"],
        },
      ],
      role_fit_assessment: {
        immediate_readiness: "medium",
        growth_potential: "medium",
        culture_fit_indicators: ["Analysis incomplete"],
        red_flags: ["Analysis incomplete - please retry"],
      },
      keyword_analysis: {
        matched_keywords: ["Analysis incomplete"],
        missing_keywords: ["Analysis incomplete"],
        keyword_density_score: 0,
      },
      recommendations: {
        for_candidate: ["Analysis incomplete - please retry"],
        for_recruiter: ["Analysis incomplete - please retry"],
        interview_focus_areas: ["Analysis incomplete - please retry"],
      },
    };
  }

  /**
   * Creates a more concise analysis prompt to avoid token limits
   */
  createAnalysisPrompt(jobDescription, resume) {
    return `You are an expert HR analyst and ATS system. Carefully analyze the resume against the job description and provide a precise similarity score based on strict criteria.
 
 
 JOB DESCRIPTION:
 ${jobDescription}
 
 
 RESUME:
 ${resume}
 
 
 CRITICAL SCORING GUIDELINES - Be precise and strict:
 
 
 🎯 PERFECT MATCH (85-100 points):
 - 90%+ of required skills are present and well-demonstrated
 - Experience level matches or exceeds requirements
 - Job title/role closely aligns with target position
 - Industry experience is directly relevant
 - Educational requirements fully met
 - Strong evidence of achievements in similar roles
 
 
 ⭐ GOOD MATCH (70-84 points):
 - 70-89% of required skills are present
 - Experience level is adequate (within 1-2 years of requirement)
 - Role has significant overlap with target position
 - Most qualifications are met
 - Some relevant industry experience
 
 
 🔶 MODERATE MATCH (50-69 points):
 - 40-69% of required skills are present
 - Experience level has some gaps but shows potential
 - Role has partial overlap or transferable skills
 - Some qualifications missing but core competencies exist
 - Limited but relevant experience
 
 
 ⚠️ WEAK MATCH (25-49 points):
 - 20-39% of required skills are present
 - Significant experience gaps
 - Role requires substantial upskilling
 - Major qualifications missing
 - Minimal relevant experience
 
 
 ❌ POOR MATCH (0-24 points):
 - <20% of required skills are present
 - Completely different field or role
 - No relevant experience
 - Missing critical qualifications
 - Not suitable for the position
 
 
 IMPORTANT: Return ONLY valid JSON. Use proper escaping for quotes in strings. Do not include newlines within string values.
 
 
 {
  "overall_similarity_score": 75,
  "matching_strengths": {
    "hard_skills": ["list specific matching technical skills from resume"],
    "soft_skills": ["list specific matching soft skills from resume"],
    "experience_areas": ["list relevant experience areas that match job requirements"],
    "qualifications": ["list matching educational/certification qualifications"],
    "achievements": ["list relevant achievements that align with job needs"]
  },
  "missing_critical_elements": {
    "hard_skills": ["list specific missing technical skills mentioned in job description"],
    "soft_skills": ["list missing soft skills from job requirements"],
    "experience_gaps": ["list missing experience areas or insufficient experience level"],
    "qualifications": ["list missing educational/certification requirements"],
    "other_requirements": ["list any other missing job requirements"]
  },
  "recommendations": {
    "for_candidate": ["specific recommendations for candidate to improve fit"],
    "for_recruiter": ["insights for recruiter about this candidate"],
  }
 }
  CRITICAL: Return ONLY the JSON object. Start with { and end with }.
  IMPORTANT:
  - Output ONLY the JSON object. No explanations, no preambles, no markdown (e.g. don't wrap in json)
  - Do not insert newlines in string values.
  - Output should start with { and end with }`;
  }

  /**
   * Validates and enhances the AI response
   */
  validateAndEnhanceResponse(analysis) {
    const requiredFields = [
      "overall_similarity_score",
      "matching_strengths",
      "missing_critical_elements",
      "role_fit_assessment",
      "recommendations",
    ];

    for (const field of requiredFields) {
      if (!analysis[field]) {
        console.warn(`Missing field ${field}, using default`);
        analysis[field] = this.getDefaultFieldValue(field);
      }
    }

    // Ensure similarity score is valid
    if (
      typeof analysis.overall_similarity_score !== "number" ||
      analysis.overall_similarity_score < 0 ||
      analysis.overall_similarity_score > 100
    ) {
      analysis.overall_similarity_score = 50;
    }

    // Add metadata
    analysis.analysis_metadata = {
      timestamp: new Date().toISOString(),
      model_used: "gemini-1.5-flash",
      analysis_version: "2.0",
      parsing_method: "enhanced",
    };

    return analysis;
  }

  /**
   * Validate simple response structure
   */
  validateAndEnhanceSimpleResponse(analysis) {
    // Fill any missing fields with defaults
    const template = this.getBasicAnalysisStructure();
    const merged = this.fillMissingFields(analysis);

    merged.analysis_metadata = {
      timestamp: new Date().toISOString(),
      model_used: "gemini-1.5-flash",
      analysis_version: "2.0-fallback",
      parsing_method: "fallback",
    };

    return merged;
  }

  /**
   * Get default value for missing fields
   */
  getDefaultFieldValue(fieldName) {
    const defaults = {
      overall_similarity_score: 50,
      matching_strengths: {
        hard_skills: [],
        soft_skills: [],
        experience_areas: [],
        qualifications: [],
        achievements: [],
      },
      missing_critical_elements: {
        hard_skills: [],
        soft_skills: [],
        experience_gaps: [],
        qualifications: [],
        other_requirements: [],
      },
      areas_for_improvement: [],
      role_fit_assessment: {
        immediate_readiness: "medium",
        growth_potential: "medium",
        culture_fit_indicators: [],
        red_flags: [],
      },
      keyword_analysis: {
        matched_keywords: [],
        missing_keywords: [],
        keyword_density_score: 0,
      },
      recommendations: {
        for_candidate: [],
        for_recruiter: [],
        interview_focus_areas: [],
      },
    };

    return defaults[fieldName] || {};
  }

  /**
   * Batch analyze with better error handling
   */
  async batchAnalyze(jobDescription, resumes, delayMs = 5000) {
    const results = [];
    let consecutiveFailures = 0;
    const maxConsecutiveFailures = 3;

    for (let i = 0; i < resumes.length; i++) {
      const { id, resume } = resumes[i];

      try {
        console.log(`Analyzing resume ${i + 1}/${resumes.length} (ID: ${id})`);

        const analysis = await this.analyzeResumeMatch(jobDescription, resume);
        results.push({
          resume_id: id,
          analysis: analysis,
          status: "success",
        });

        consecutiveFailures = 0; // Reset counter on success

        // Rate limiting delay
        if (i < resumes.length - 1) {
          await this.delay(delayMs);
        }
      } catch (error) {
        consecutiveFailures++;
        console.error(`Failed to analyze resume ${id}:`, error.message);

        results.push({
          resume_id: id,
          analysis: null,
          status: "error",
          error: error.message,
        });

        // If too many consecutive failures, increase delay
        if (consecutiveFailures >= maxConsecutiveFailures) {
          console.log("Multiple consecutive failures, increasing delay...");
          await this.delay(delayMs * 2);
          consecutiveFailures = 0;
        }
      }
    }

    return results;
  }

  /**
   * Utility function for delays
   */
  delay(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  /**
   * Generate a summary report for batch analysis
   */
  generateBatchSummary(batchResults) {
    const successful = batchResults.filter((r) => r.status === "success");
    const failed = batchResults.filter((r) => r.status === "error");

    if (successful.length === 0) {
      return {
        error: "No successful analyses to summarize",
        total_resumes: batchResults.length,
        failed_analyses: failed.length,
        failure_rate:
          ((failed.length / batchResults.length) * 100).toFixed(1) + "%",
      };
    }

    const scores = successful.map((r) => r.analysis.overall_similarity_score);
    const avgScore = scores.reduce((a, b) => a + b, 0) / scores.length;

    return {
      total_resumes: batchResults.length,
      successful_analyses: successful.length,
      failed_analyses: failed.length,
      success_rate:
        ((successful.length / batchResults.length) * 100).toFixed(1) + "%",
      average_similarity_score: Math.round(avgScore * 100) / 100,
      highest_score: Math.max(...scores),
      lowest_score: Math.min(...scores),
      top_candidates: successful
        .sort(
          (a, b) =>
            b.analysis.overall_similarity_score -
            a.analysis.overall_similarity_score
        )
        .slice(0, 5)
        .map((r) => ({
          resume_id: r.resume_id,
          score: r.analysis.overall_similarity_score,
          immediate_readiness:
            r.analysis.role_fit_assessment?.immediate_readiness || "unknown",
        })),
    };
  }
}

// Usage Example with error handling
async function example() {
  const analyzer = new ResumeJDAnalyzer("YOUR_GEMINI_API_KEY");

  const jobDescription = `
    Senior Software Engineer
    We are looking for a Senior Software Engineer to join our team...
    Requirements: 5+ years experience, JavaScript, React, Node.js, AWS...
  `;

  const resume = `
    John Doe
    Software Engineer with 6 years of experience...
    Skills: JavaScript, React, Python, Docker...
  `;

  try {
    const analysis = await analyzer.analyzeResumeMatch(jobDescription, resume);
    console.log("Analysis Result:", JSON.stringify(analysis, null, 2));
  } catch (error) {
    console.error("Analysis failed:", error.message);

    // The analyzer now has built-in fallbacks, so this should rarely happen
    // But if it does, you can still get a basic structure
  }
}

export default ResumeJDAnalyzer;
export { ResumeJDAnalyzer };

//  {
//   "overall_similarity_score": 5,
//   "matching_strengths": {
//     "hard_skills": [],
//     "soft_skills": [],
//     "experience_areas": [],
//     "qualifications": [],
//     "achievements": []
//   },
//   "missing_critical_elements": {
//     "hard_skills": [
//       "English literature lesson planning and delivery",
//       "grammar lesson planning and delivery",
//       "standardized exam preparation",
//       "college readiness preparation",
//       "student performance evaluation",
//       "progress report maintenance",
//       "curriculum development",
//       "educational technology platforms familiarity"
//     ],
//     "soft_skills": [
//       "classroom management skills",
//       "fostering a positive learning environment"
//     ],
//     "experience_gaps": [
//       "3+ years of classroom teaching experience (grades 9-12)"
//     ],
//     "qualifications": [
//       "Bachelor’s degree in English or Education",
//       "Teaching license or certification (State of CA)"
//     ],
//     "other_requirements": []
//   },
//   "recommendations": {
//     "for_candidate": [
//       "Pursue roles aligned with photography and visual arts.",
//       "If interested in teaching, acquire a relevant Bachelor's degree, teaching certification, and gain practical classroom experience."
//     ],
//     "for_recruiter": [
//       "This candidate is not suitable for the High School English Teacher position due to a complete lack of relevant experience, education, and certification.",
//       "Do not proceed with this application."
//     ],

//   },
//   "analysis_metadata": {
//     "timestamp": "2025-06-23T12:34:56.841Z",
//     "model_used": "gemini-1.5-flash",
//     "analysis_version": "2.0",
//     "parsing_method": "enhanced"
//   }
// }
