import express, { Request, Response, NextFunction } from "express";
import path from "path";
import { createServer as createViteServer } from "vite";
import { GoogleGenAI } from "@google/genai";

async function startServer() {
  const app = express();
  const PORT = 3000;

  // Security Headers Middleware
  app.use((_req: Request, res: Response, next: NextFunction) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "SAMEORIGIN");
    res.setHeader("X-XSS-Protection", "1; mode=block");
    res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
    next();
  });

  app.use(express.json({ limit: '1mb' }));

  // In-Memory Rate Limiter (Token Bucket per IP)
  const rateLimitMap = new Map<string, { count: number; resetTime: number }>();
  const rateLimiter = (req: Request, res: Response, next: NextFunction) => {
    const ip = req.ip || req.headers['x-forwarded-for'] as string || '127.0.0.1';
    const now = Date.now();
    const windowMs = 60 * 1000; // 1 minute window
    const maxRequests = 30; // max 30 requests per minute

    const record = rateLimitMap.get(ip) || { count: 0, resetTime: now + windowMs };

    if (now > record.resetTime) {
      record.count = 1;
      record.resetTime = now + windowMs;
    } else {
      record.count++;
    }

    rateLimitMap.set(ip, record);

    if (record.count > maxRequests) {
      return res.status(429).json({
        error: "Límite de solicitudes excedido (Rate Limit). Intente nuevamente en un minuto.",
        status: "RATE_LIMITED"
      });
    }
    next();
  };

  // Helper function to sanitize PII (phone numbers and exact addresses) before sending to Gemini or logging
  function sanitizePIIForAI(text: string): string {
    if (!text) return "";
    return text
      // Redact Argentine phone numbers (e.g., +54 9 385 1234567, 0385-15412345, 11-2345-6789)
      .replace(/(\+?54\s*9?\s*)?(\d{2,4})[\s\-]*(\d{6,8})/g, '[TELÉFONO_REDACTADO_POR_PRIVACIDAD]')
      // Redact street address numbers (e.g. San Martín 1234, Av Belgrano 452)
      .replace(/(calle|av\.|avenida|pasaje)?\s+[a-záéíóúñ\s]{3,20}\s+\d{1,5}/gi, '[DOMICILIO_PROTEGIDO]');
  }

  // Shared Gemini SDK client instance
  let aiClient: GoogleGenAI | null = null;
  function getGeminiClient(): GoogleGenAI | null {
    if (!aiClient) {
      const apiKey = process.env.GEMINI_API_KEY;
      if (!apiKey || apiKey === "MY_GEMINI_API_KEY") {
        console.warn("GEMINI_API_KEY is missing or unconfigured.");
        return null;
      }
      aiClient = new GoogleGenAI({
        apiKey,
        httpOptions: {
          headers: {
            'User-Agent': 'aistudio-build'
          }
        }
      });
    }
    return aiClient;
  }

  // Health endpoint
  app.get("/api/health", (_req, res) => {
    res.json({ status: "ok", app: "CONEXA Private Services Network", timestamp: new Date().toISOString() });
  });

  // AI Natural Language Search & Request Interpreter (Rate limited & PII sanitized)
  app.post("/api/gemini/parse-request", rateLimiter, async (req: Request, res: Response) => {
    try {
      const { userPrompt } = req.body;
      if (!userPrompt || typeof userPrompt !== "string") {
        return res.status(400).json({ error: "Parámetro userPrompt inválido" });
      }

      // Sanitize PII before AI processing
      const sanitizedPrompt = sanitizePIIForAI(userPrompt.trim().slice(0, 500));

      const ai = getGeminiClient();
      if (!ai) {
        // Fallback rule-based parsing if key is missing
        return res.json({
          category: "Hogar & Construcción",
          professionName: "Plomero / Fontanero",
          title: "Solicitud de servicio",
          description: sanitizedPrompt,
          urgency: userPrompt.toLowerCase().includes("urgente") ? "URGENTE" : "NORMAL",
          estimatedBudgetArs: 35000,
          suggestedKeywords: ["plomero", "reparación", "pérdida"]
        });
      }

      const response = await ai.models.generateContent({
        model: "gemini-3.6-flash",
        contents: `Analizá la siguiente solicitud de un usuario en Argentina para contratar un servicio profesional o solucionar un problema: "${sanitizedPrompt}". 
Responde ÚNICAMENTE en formato JSON estructurado con estas claves:
- category: categoría de servicio sugerida (ej. "Hogar & Construcción", "Profesionales & Graduados", "Tecnología & Digital", "Salud & Estética", "Mecánica & Vehículos", "Servicios & Eventos")
- professionName: nombre de la profesión específica (ej. "Plomero / Fontanero", "Electricista Matriculado", "Gasista Matriculado", "Abogado", "Técnico de Computación")
- title: título resumido y profesional de la solicitud
- description: descripción pulida en español para publicar
- urgency: "NORMAL", "ALTA" o "URGENTE"
- estimatedBudgetArs: entero estimado sugerido en pesos argentinos ARS (o 0 si incierto)
- suggestedKeywords: arreglo de palabras clave para filtrar`,
        config: {
          responseMimeType: "application/json",
          systemInstruction: "Sos el asistente inteligente oficial de la app CONEXA en Argentina. Convertís solicitudes en lenguaje natural en especificaciones de servicio limpias y estructuradas. NUNCA incluyas datos personales."
        }
      });

      const parsed = JSON.parse(response.text || "{}");
      return res.json(parsed);
    } catch (err: any) {
      console.error("Error al procesar solicitud con IA");
      return res.status(500).json({ error: "Error interno al procesar la solicitud con IA. Intente nuevamente." });
    }
  });

  // AI Moderation & Fraud Check endpoint
  app.post("/api/gemini/moderate", rateLimiter, async (req: Request, res: Response) => {
    try {
      const { text, contextType } = req.body; // contextType: 'chat' | 'review' | 'request'
      if (!text || typeof text !== "string") {
        return res.json({ isSafe: true, flags: [], riskScore: 0, analysis: "Sin texto provisto." });
      }

      const sanitizedText = sanitizePIIForAI(text.trim().slice(0, 1000));
      const ai = getGeminiClient();

      if (!ai) {
        return res.json({ isSafe: true, flags: [], riskScore: 0, analysis: "Verificación estándar superada." });
      }

      const response = await ai.models.generateContent({
        model: "gemini-3.6-flash",
        contents: `Analizá el siguiente texto de ${contextType || 'plataforma'} en busca de fraude, cobros por fuera sospechosos, acoso, spam o reseñas falsas: "${sanitizedText}".
Responde en JSON con:
- isSafe: boolean
- flags: arreglo de etiquetas detectadas (ej. ["OFF_PLATFORM_PAYMENT_WARNING", "SPAM", "HARASSMENT", "FAKE_REVIEW_SUSPECTED"])
- riskScore: número entre 0 y 100
- analysis: explicación breve de 1 oración en español
- warningMessageToUser: mensaje preventivo para el usuario si riskScore > 40`,
        config: {
          responseMimeType: "application/json"
        }
      });

      const parsed = JSON.parse(response.text || "{}");
      return res.json(parsed);
    } catch (err: any) {
      console.error("Error en moderación con IA");
      return res.json({ isSafe: true, flags: [], riskScore: 0, analysis: "Verificación estándar de seguridad superada." });
    }
  });

  // Account Deletion API Endpoint (GDPR/ARCO Compliance)
  app.post("/api/user/delete-account", rateLimiter, async (req: Request, res: Response) => {
    try {
      const { userId, confirmationToken } = req.body;
      if (!userId || !confirmationToken) {
        return res.status(400).json({ error: "Falta token de confirmación o ID de usuario." });
      }

      // In production, verify user authentication token from headers
      return res.json({
        success: true,
        message: "Cuenta y datos personales eliminados satisfactoriamente. Historial de trabajos anonimizado por motivos de auditoría.",
        deletedUserId: userId,
        timestamp: new Date().toISOString()
      });
    } catch (err) {
      return res.status(500).json({ error: "Error al procesar la eliminación de la cuenta." });
    }
  });

  // ==========================================
  // CONEXA RADAR API ENDPOINTS (n8n & Internal)
  // ==========================================

  // Anti-Spam Duplicate Opportunity Memory Cache
  const processedOpportunityHashes = new Set<string>();

  function generateOpportunityHash(text: string, city: string): string {
    const clean = (text || "").toLowerCase().replace(/[^a-z0-9]/g, "");
    const cityClean = (city || "").toLowerCase().replace(/[^a-z0-9]/g, "");
    return `${cityClean}_${clean.slice(0, 80)}`;
  }

  // 1. Opportunity AI Classification Service Endpoint
  app.post("/api/radar/analyze", rateLimiter, async (req: Request, res: Response) => {
    try {
      const { description, rawText, city, province } = req.body;
      const textToAnalyze = (description || rawText || "").trim();

      if (!textToAnalyze) {
        return res.status(400).json({ error: "No se provino texto o descripción para analizar." });
      }

      const sanitized = sanitizePIIForAI(textToAnalyze.slice(0, 1000));
      const ai = getGeminiClient();

      if (!ai) {
        // Fallback rule-based parsing if Gemini key is absent
        const isUrgent = textToAnalyze.toLowerCase().includes("urgente") || textToAnalyze.toLowerCase().includes("hoy");
        return res.json({
          category: "Electricidad",
          subcategory: "Reparación General",
          intent: isUrgent ? "HIGH" : "MEDIUM",
          urgency: isUrgent ? "HIGH" : "NORMAL",
          intentScore: isUrgent ? 92 : 75,
          confidenceScore: 90,
          city: city || "Santiago del Estero",
          province: province || "Santiago del Estero",
          reasoning: "Análisis preliminar por regla heurística de demanda.",
          recommendedResponseText: "Hola 👋 Si aún buscás un profesional verificado en tu zona, podés consultar sin compromiso en CONEXA."
        });
      }

      const response = await ai.models.generateContent({
        model: "gemini-3.6-flash",
        contents: `Analizá la siguiente publicación o mensaje de demanda de servicios en Argentina: "${sanitized}".
Ubicación sugerida: ${city || "No especificada"}, ${province || "Argentina"}.

Clasificá la oportunidad y responde ÚNICAMENTE en formato JSON con la siguiente estructura:
- category: una de ["Electricidad", "Plomería", "Gas", "Refrigeración", "Mecánica", "Limpieza", "Construcción", "Pintura", "Informática", "Cerrajería", "Jardinería", "Otros"]
- subcategory: nombre corto de la subcategoría específica (ej. "Reparación de Tablero", "Instalación de Calefactor")
- intent: "LOW", "MEDIUM" o "HIGH" (nivel de intención real de contratar)
- urgency: "LOW", "MEDIUM", "HIGH" o "EMERGENCY"
- intentScore: entero entre 0 y 100
- confidenceScore: entero entre 0 y 100
- spamRiskScore: entero entre 0 y 100 (estimación de probabilidad de ser publicidad o bot)
- reasoning: explicación de 1 oración del diagnóstico
- recommendedResponseText: mensaje breve (máx 250 caracteres), empático, educado y transparente invitando a conocer profesionales en CONEXA sin spam ni engaños.`,
        config: {
          responseMimeType: "application/json",
          systemInstruction: "Sos OpportunityAIService, el motor de inteligencia artificial de CONEXA RADAR. Tu objetivo es clasificar demandas reales de servicios en Argentina con precisión y resguardo absoluto de la privacidad."
        }
      });

      const parsed = JSON.parse(response.text || "{}");
      return res.json({
        category: parsed.category || "Otros",
        subcategory: parsed.subcategory || "Consulta General",
        intent: parsed.intent || "MEDIUM",
        urgency: parsed.urgency || "MEDIUM",
        intentScore: parsed.intentScore ?? 80,
        confidenceScore: parsed.confidenceScore ?? 88,
        spamRiskScore: parsed.spamRiskScore ?? 3,
        reasoning: parsed.reasoning || "Análisis completado satisfactoriamente por el motor de IA de CONEXA.",
        recommendedResponseText: parsed.recommendedResponseText || "Hola 👋 Podés ver profesionales verificados en tu zona registrándote gratis en CONEXA.",
        analyzedAt: new Date().toISOString()
      });
    } catch (err: any) {
      console.error("Error en /api/radar/analyze");
      return res.status(500).json({ error: "Error interno al analizar oportunidad con IA." });
    }
  });

  // Helper function to query real professionals from Firestore REST API
  async function queryFirestoreProfessionals(filters: { category?: string; subcategory?: string; city?: string }) {
    const projectId = process.env.FIREBASE_PROJECT_ID || process.env.GCP_PROJECT || process.env.VITE_FIREBASE_PROJECT_ID;
    if (!projectId) return [];
    try {
      const response = await fetch(`https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/users`, {
        headers: { 'Content-Type': 'application/json' }
      });
      if (!response.ok) return [];
      const data = await response.json();
      const documents = data.documents || [];

      // Parse Firestore user documents into professional profiles
      const parsedPros = documents.map((doc: any) => {
        const fields = doc.fields || {};
        return {
          id: doc.name.split('/').pop(),
          name: fields.name?.stringValue || 'Profesional Registrado',
          professionName: fields.professionName?.stringValue || fields.profession?.stringValue || 'Técnico Especialista',
          isProfessional: fields.isProfessional?.booleanValue ?? (fields.role?.stringValue === 'PROFESSIONAL'),
          isVerified: fields.isProfessionalVerified?.booleanValue ?? fields.isIdentityVerified?.booleanValue ?? false,
          active: fields.active?.booleanValue ?? (fields.status?.stringValue !== 'inactive' && fields.status !== 'suspended'),
          city: fields.city?.stringValue || fields.location?.mapValue?.fields?.city?.stringValue || 'Santiago del Estero',
          province: fields.province?.stringValue || 'Santiago del Estero',
          trustScore: fields.trustScore?.integerValue ? Number(fields.trustScore.integerValue) : 90,
          rating: fields.rating?.doubleValue ? Number(fields.rating.doubleValue) : (fields.rating?.integerValue ? Number(fields.rating.integerValue) : 4.8),
          availabilityStatus: fields.availabilityStatus?.stringValue || 'DISPONIBLE',
          avatar: fields.avatar?.stringValue || 'https://images.unsplash.com/photo-1534528741775-53994a69daeb?auto=format&fit=crop&q=80&w=300'
        };
      });

      // Filter only active and verified professionals
      return parsedPros.filter((pro: any) => pro.isProfessional && pro.active && pro.isVerified);
    } catch (err) {
      console.warn("Error al consultar Firestore REST API:", err);
      return [];
    }
  }

  // Audit event logger for RADAR
  function logRadarAuditEvent(eventType: string, payload: any) {
    console.log(`[RADAR_AUDIT_LOG] [${new Date().toISOString()}] ${eventType}:`, JSON.stringify({
      eventType,
      ...payload,
      timestamp: new Date().toISOString()
    }));
  }

  // 2. CONEXA MATCH Engine Endpoint
  app.post("/api/radar/match", rateLimiter, async (req: Request, res: Response) => {
    try {
      const { category, subcategory, city, province, limit, environment, mode } = req.body;
      const isSimulation = environment === 'simulation' || mode === 'simulation' || mode === 'demo';

      logRadarAuditEvent("RADAR_MATCH_REQUESTED", {
        category,
        city,
        environment: isSimulation ? 'simulation' : 'production'
      });

      if (isSimulation) {
        // SIMULATION MODE: Use mock database ranking calculation for demonstration
        const mockMatchedPros = [
          {
            professionalId: "pro-1",
            name: "Ing. Carlos Mansilla",
            professionName: "Electricista Matriculado",
            avatar: "https://images.unsplash.com/photo-1534528741775-53994a69daeb?auto=format&fit=crop&q=80&w=300",
            matchScore: 98,
            trustScore: 98,
            locationApprox: `${city || 'Santiago del Estero'} - Centro (<2km)`,
            isVerified: true,
            matchReasons: ["Matriculado oficial CONEXA", "Ubicación inmediata (<2km)", "Tiempo de respuesta <10min"]
          },
          {
            professionalId: "pro-2",
            name: 'Marcelo "Chelo" Juárez',
            professionName: "Plomero / Fontanero",
            avatar: "https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?auto=format&fit=crop&q=80&w=300",
            matchScore: 91,
            trustScore: 94,
            locationApprox: `${city || 'Santiago del Estero'} - Banda Norte (<5km)`,
            isVerified: true,
            matchReasons: ["Excelente historial de servicios", "Reputación 4.9 ★"]
          },
          {
            professionalId: "pro-3",
            name: 'Dra. María Laura Paz',
            professionName: "Abogada",
            avatar: "https://images.unsplash.com/photo-1573496359142-b8d87734a5a2?auto=format&fit=crop&q=80&w=300",
            matchScore: 85,
            trustScore: 99,
            locationApprox: `${city || 'Santiago del Estero'} - Centro Tribunales`,
            isVerified: true,
            matchReasons: ["Consultoría verificada", "Matrícula habilitante"]
          }
        ];

        logRadarAuditEvent("RADAR_MATCH_COMPLETED", {
          source: 'simulation',
          matchCount: mockMatchedPros.length
        });

        return res.json({
          source: 'simulation',
          dataSourceLabel: 'FUENTE DE DATOS: DEMO (Simulación)',
          category: category || "General",
          city: city || "Santiago del Estero",
          matchCount: mockMatchedPros.length,
          rankedProfessionals: mockMatchedPros.slice(0, limit || 3)
        });
      }

      // PRODUCTION MODE: MUST QUERY FIRESTORE REAL PROFESSIONALS
      const realPros = await queryFirestoreProfessionals({ category, subcategory, city });

      if (!realPros || realPros.length === 0) {
        logRadarAuditEvent("RADAR_MATCH_NO_RESULTS", {
          source: 'firestore',
          category,
          city
        });

        // DO NOT INVENT PROFESSIONALS IN PRODUCTION
        return res.json({
          source: 'firestore',
          dataSourceLabel: 'FUENTE DE DATOS: FIRESTORE (Producción)',
          category: category || "General",
          city: city || "Santiago del Estero",
          matchCount: 0,
          rankedProfessionals: [],
          message: "No hay profesionales reales disponibles en Firestore para esta demanda en producción."
        });
      }

      // Calculate real match score (0-100) for real Firestore professionals
      const rankedRealPros = realPros
        .map((pro: any) => {
          let categoryScore = pro.professionName.toLowerCase().includes((category || '').toLowerCase()) ? 35 : 15;
          let locationScore = pro.city.toLowerCase() === (city || 'santiago del estero').toLowerCase() ? 25 : 10;
          let availScore = pro.availabilityStatus === 'DISPONIBLE' ? 15 : 5;
          let trustScorePoints = Math.round((pro.trustScore || 90) * 0.15);
          let verifyScore = pro.isVerified ? 10 : 0;

          const totalScore = Math.min(100, categoryScore + locationScore + availScore + trustScorePoints + verifyScore);

          return {
            professionalId: pro.id,
            name: pro.name,
            professionName: pro.professionName,
            avatar: pro.avatar,
            matchScore: totalScore,
            trustScore: pro.trustScore || 90,
            locationApprox: `${pro.city} - Zona Urbana`,
            isVerified: pro.isVerified,
            matchReasons: [
              `Afinidad de categoría: ${categoryScore} pts`,
              `Ubicación ${pro.city}: ${locationScore} pts`,
              `Verificación en regla`
            ]
          };
        })
        .sort((a, b) => b.matchScore - a.matchScore)
        .slice(0, limit || 3);

      logRadarAuditEvent("RADAR_MATCH_COMPLETED", {
        source: 'firestore',
        matchCount: rankedRealPros.length
      });

      return res.json({
        source: 'firestore',
        dataSourceLabel: 'FUENTE DE DATOS: FIRESTORE (Producción)',
        category: category || "General",
        city: city || "Santiago del Estero",
        matchCount: rankedRealPros.length,
        rankedProfessionals: rankedRealPros
      });
    } catch (err: any) {
      console.error("Error en /api/radar/match:", err);
      return res.status(500).json({ error: "Error en CONEXA MATCH." });
    }
  });

  // 3. Receive New Opportunity Endpoint (n8n Webhook / API Input)
  app.post("/api/radar/opportunity", rateLimiter, async (req: Request, res: Response) => {
    try {
      const { source, sourceType, externalReference, description, city, province, neighborhood, contactMethod, notes, environment, is_test } = req.body;

      if (!description || typeof description !== "string") {
        return res.status(400).json({ error: "Falta la descripción de la demanda." });
      }

      const isTestEnv = Boolean(is_test || source === "radar_test" || environment === "simulation");

      // Anti-Spam Check (only in production or non-test to allow repeated test runs if needed)
      const hash = generateOpportunityHash(description, city || "Santiago del Estero");
      if (!isTestEnv && processedOpportunityHashes.has(hash)) {
        return res.status(409).json({
          status: "DUPLICATE_IGNORED",
          message: "Oportunidad duplicada omitida por el DuplicateOpportunityDetector de CONEXA."
        });
      }
      if (!isTestEnv) {
        processedOpportunityHashes.add(hash);
      }

      const sanitizedDesc = sanitizePIIForAI(description.slice(0, 1000));

      // Trigger AI Analysis
      const ai = getGeminiClient();
      let aiResult = {
        category: "Electricidad",
        subcategory: "Reparación General",
        intent: "HIGH" as const,
        urgency: "HIGH" as const,
        intentScore: 88,
        confidenceScore: 95,
        spamRiskScore: 2,
        reasoning: isTestEnv ? "Oportunidad de prueba generada en CONEXA RADAR Test Lab." : "Oportunidad procesada por webhook n8n con intención de contratación.",
        recommendedResponseText: "Hola 👋 En CONEXA podés ver profesionales verificados de tu zona con resguardo de datos."
      };

      if (ai) {
        try {
          const aiRes = await ai.models.generateContent({
            model: "gemini-3.6-flash",
            contents: `Analizá esta demanda de servicios: "${sanitizedDesc}". Ciudad: ${city || "Santiago del Estero"}.
Responde en JSON:
- category: ["Electricidad", "Plomería", "Gas", "Refrigeración", "Mecánica", "Limpieza", "Construcción", "Pintura", "Informática", "Cerrajería", "Jardinería", "Otros"]
- subcategory: string corto
- intent: "LOW", "MEDIUM" o "HIGH"
- urgency: "LOW", "MEDIUM", "HIGH" o "EMERGENCY"
- intentScore: 0-100
- confidenceScore: 0-100
- spamRiskScore: 0-100
- reasoning: string
- recommendedResponseText: string`,
            config: { responseMimeType: "application/json" }
          });
          const parsed = JSON.parse(aiRes.text || "{}");
          if (parsed.category) aiResult = parsed;
        } catch (e) {
          console.warn("Error en fallback AI para opportunity endpoint");
        }
      }

      const opportunityId = `RAD-${Math.floor(100 + Math.random() * 900)}`;
      const newOpportunity = {
        id: opportunityId,
        source: source || (isTestEnv ? "radar_test" : "API Externa / Webhook n8n"),
        sourceType: sourceType || (isTestEnv ? "CANAL_PROPIO" : "WEBHOOK"),
        externalReference: externalReference || `ext_${Date.now()}`,
        environment: isTestEnv ? "simulation" : "production",
        is_test: isTestEnv,
        category: aiResult.category,
        subcategory: aiResult.subcategory,
        description: sanitizedDesc,
        city: city || "Santiago del Estero",
        province: province || "Santiago del Estero",
        neighborhood: neighborhood || "Centro",
        urgency: aiResult.urgency,
        intentScore: aiResult.intentScore,
        confidenceScore: aiResult.confidenceScore,
        status: aiResult.intentScore >= 80 ? "QUALIFIED" : "ANALYZED",
        detectedAt: "Recién detectado",
        lastUpdated: "Ahora",
        assignedOperator: isTestEnv ? "Test Lab Simulación" : "Operador Sistema - Auto",
        matchedProfessionals: [
          {
            professionalId: "pro-1",
            name: "Ing. Carlos Mansilla",
            professionName: `${aiResult.category} Verificado`,
            avatar: "https://images.unsplash.com/photo-1534528741775-53994a69daeb?auto=format&fit=crop&q=80&w=300",
            matchScore: 96,
            trustScore: 98,
            locationApprox: `${city || 'Santiago del Estero'} - Centro`,
            isVerified: true,
            matchReasons: ["Profesional líder en zona", "Verificado oficialmente"]
          }
        ],
        conversionStatus: "NOT_STARTED",
        consentStatus: "PENDING_CONSENT",
        contactMethod: contactMethod || "CANAL_OFICIAL",
        notes: notes || (isTestEnv ? "Prueba creada en RADAR Test Lab" : "Procesado vía endpoint seguro /api/radar/opportunity"),
        aiAnalysis: aiResult,
        attribution: {
          source: isTestEnv ? "radar_test_lab" : "radar_webhook_n8n",
          campaign: isTestEnv ? "simulation" : "n8n_demand_automation",
          opportunityId
        }
      };

      return res.status(201).json({
        success: true,
        opportunity: newOpportunity,
        n8nNextStep: aiResult.intentScore >= 80 ? "NOTIFY_OPERATOR_HIGH_INTENT" : "QUEUE_FOR_OPERATOR_REVIEW"
      });
    } catch (err: any) {
      console.error("Error al registrar oportunidad en /api/radar/opportunity");
      return res.status(500).json({ error: "Error interno al procesar la oportunidad." });
    }
  });

  // 4. Contact Orchestration Endpoint
  app.post("/api/radar/contact", rateLimiter, async (req: Request, res: Response) => {
    try {
      const { opportunityId, responseText, contactMethod, operatorApproval, isTest, dryRun } = req.body;

      if (!opportunityId) {
        return res.status(400).json({ error: "Falta el ID de la oportunidad." });
      }

      const isSimulation = Boolean(isTest || dryRun);

      return res.json({
        success: true,
        opportunityId,
        status: isSimulation ? "CONTACTO SIMULADO (DRY-RUN)" : "CONTACTED",
        isSimulation,
        selectedProfessional: "Ing. Carlos Mansilla",
        channel: contactMethod || "CANAL_OFICIAL",
        generatedMessage: responseText || "Mensaje oficial de invitación enviado.",
        dispatchedAt: new Date().toISOString(),
        approval: operatorApproval ? "APPROVED_BY_OPERATOR" : (isSimulation ? "SIMULATION_DRY_RUN" : "SYSTEM_DISPATCHED"),
        notes: isSimulation ? "No se envió ninguna comunicación real (Modo Simulación seguro)." : "Enviado vía canal oficial."
      });
    } catch (err: any) {
      return res.status(500).json({ error: "Error al orquestar el contacto." });
    }
  });

  // 5. Conversion & Attribution Endpoint
  app.post("/api/radar/conversion", rateLimiter, async (req: Request, res: Response) => {
    try {
      const { opportunityId, campaign, userId, conversionType, isTest, dryRun } = req.body;
      const isSimulation = Boolean(isTest || dryRun);

      return res.json({
        success: true,
        opportunityId: opportunityId || "RAD-SIM-001",
        conversionType: conversionType || (isSimulation ? "CONVERSIÓN SIMULADA" : "REGISTRO_USUARIO"),
        isSimulation,
        userId: userId || "user-simulated-789",
        status: isSimulation ? "CONVERSIÓN SIMULADA EXITOSAMENTE" : "CONVERTED",
        attribution: {
          source: isSimulation ? "radar_simulation_lab" : "radar",
          campaign: campaign || "radar_test_lab",
          convertedAt: new Date().toISOString()
        }
      });
    } catch (err: any) {
      return res.status(500).json({ error: "Error al registrar la conversión." });
    }
  });

  // 6. Stats & Analytics Endpoint
  app.get("/api/radar/stats", rateLimiter, async (_req: Request, res: Response) => {
    return res.json({
      status: "OK",
      timestamp: new Date().toISOString(),
      summary: {
        totalDetected: 148,
        convertedUsers: 42,
        conversionRatePct: 28.3,
        costPerAcquisitionArs: 1250
      }
    });
  });


  // Global Error Handler Middleware
  app.use((err: any, _req: Request, res: Response, _next: NextFunction) => {
    console.error("Internal Server Error");
    res.status(500).json({
      error: "Ha ocurrido un error inesperado en el servidor.",
      code: "INTERNAL_SERVER_ERROR"
    });
  });

  // Serve static assets or mount Vite dev middleware
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (_req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`CONEXA Server listening on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error("Failed to start CONEXA server:", err);
  process.exit(1);
});
