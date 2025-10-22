// --- 1. Importar herramientas ---
const express = require('express');
const cors = require('cors');
const fs = require('fs');
const crypto = require('crypto'); // Para generar tokens seguros

// --- 2. Cargar datos seguros a la memoria del servidor ---
const questionBanks = JSON.parse(fs.readFileSync('questions.json', 'utf8'));
const users = [
    // ¡ACTUALIZADO! Se agregan dos nuevos campos de seguridad
    { id: 0, user: 'admin', email: 'admin@paes.cl', password: 'admin', name: 'Administrador', role: 'admin', deviceToken: null, activeSessionId: null },
    { id: 1, user: 'juan.perez', email: 'juan.perez@email.com', password: '123456', name: 'Juan Pérez', role: 'student', tests: ['lectora', 'm1', 'm2'], inProgressTests: {}, deviceToken: null, activeSessionId: null },
    { id: 2, user: 'kita', email: 'kita@example.com', password: '140914', name: 'Kita', role: 'student', tests: ['lectora', 'm1', 'ciencias'], inProgressTests: {}, deviceToken: null, activeSessionId: null }
];

// --- ¡NUEVA BASE DE DATOS PARA HISTORIAL! ---
let testHistory = []; // Aquí guardaremos los resultados de las pruebas

// --- DATOS ESTÁTICOS... (Sin cambios) ---
const testDetails = {
    lectora: { name: "Competencia Lectora", time: 9000, questions: 65 },
    m1: { name: "Competencia Matemática 1 (M1)", time: 8400, questions: 65 },
    m2: { name: "Competencia Matemática 2 (M2)", time: 8400, questions: 55 },
    ciencias: { name: "Ciencias", time: 9600, questions: 80 },
    historia: { name: "Historia y Ciencias Sociales", time: 7200, questions: 65 },
};

// --- ¡CORRECCIÓN! Pegando las tablas de puntaje que estaban colapsadas ---
const scoreConversionTables = {
    lectora: [ { c: 0, p: 184 }, { c: 1, p: 251 }, { c: 2, p: 295 }, { c: 3, p: 326 }, { c: 4, p: 351 }, { c: 5, p: 372 }, { c: 6, p: 390 }, { c: 7, p: 407 }, { c: 8, p: 422 }, { c: 9, p: 436 }, { c: 10, p: 449 }, { c: 11, p: 461 }, { c: 12, p: 473 }, { c: 13, p: 484 }, { c: 14, p: 494 }, { c: 15, p: 504 }, { c: 16, p: 514 }, { c: 17, p: 524 }, { c: 18, p: 533 }, { c: 19, p: 542 }, { c: 20, p: 551 }, { c: 21, p: 560 }, { c: 22, p: 569 }, { c: 23, p: 577 }, { c: 24, p: 585 }, { c: 25, p: 594 }, { c: 26, p: 602 }, { c: 27, p: 610 }, { c: 28, p: 618 }, { c: 29, p: 626 }, { c: 30, p: 634 }, { c: 31, p: 642 }, { c: 32, p: 650 }, { c: 33, p: 658 }, { c: 34, p: 666 }, { c: 35, p: 674 }, { c: 36, p: 682 }, { c: 37, p: 690 }, { c: 38, p: 698 }, { c: 39, p: 707 }, { c: 40, p: 715 }, { c: 41, p: 724 }, { c: 42, p: 732 }, { c: 43, p: 741 }, { c: 44, p: 750 }, { c: 45, p: 759 }, { c: 46, p: 768 }, { c: 47, p: 777 }, { c: 48, p: 787 }, { c: 49, p: 797 }, { c: 50, p: 807 }, { c: 51, p: 817 }, { c: 52, p: 828 }, { c: 53, p: 839 }, { c: 54, p: 851 }, { c: 55, p: 863 }, { c: 56, p: 876 }, { c: 57, p: 890 }, { c: 58, p: 905 }, { c: 59, p: 921 }, { c: 60, p: 938 }, { c: 61, p: 956 }, { c: 62, p: 975 }, { c: 63, p: 989 }, { c: 64, p: 995 }, { c: 65, p: 1000 } ],
    m1: [ { c: 0, p: 158 }, { c: 1, p: 236 }, { c: 2, p: 286 }, { c: 3, p: 320 }, { c: 4, p: 347 }, { c: 5, p: 370 }, { c: 6, p: 390 }, { c: 7, p: 408 }, { c: 8, p: 424 }, { c: 9, p: 439 }, { c: 10, p: 453 }, { c: 11, p: 466 }, { c: 12, p: 478 }, { c: 13, p: 490 }, { c: 14, p: 501 }, { c: 15, p: 512 }, { c: 16, p: 523 }, { c: 17, p: 533 }, { c: 18, p: 543 }, { c: 19, p: 553 }, { c: 20, p: 562 }, { c: 21, p: 572 }, { c: 22, p: 581 }, { c: 23, p: 590 }, { c: 24, p: 599 }, { c: 25, p: 608 }, { c: 26, p: 617 }, { c: 27, p: 625 }, { c: 28, p: 634 }, { c: 29, p: 642 }, { c: 30, p: 651 }, { c: 31, p: 659 }, { c: 32, p: 668 }, { c: 33, p: 676 }, { c: 34, p: 685 }, { c: 35, p: 693 }, { c: 36, p: 702 }, { c: 37, p: 711 }, { c: 38, p: 720 }, { c: 39, p: 729 }, { c: 40, p: 738 }, { c: 41, p: 747 }, { c: 42, p: 757 }, { c: 43, p: 766 }, { c: 44, p: 776 }, { c: 45, p: 786 }, { c: 46, p: 796 }, { c: 47, p: 807 }, { c: 48, p: 817 }, { c: 49, p: 828 }, { c: 50, p: 840 }, { c: 51, p: 851 }, { c: 52, p: 863 }, { c: 53, p: 875 }, { c: 54, p: 888 }, { c: 55, p: 901 }, { c: 56, p: 915 }, { c: 57, p: 929 }, { c: 58, p: 944 }, { c: 59, p: 960 }, { c: 60, p: 976 }, { c: 61, p: 988 }, { c: 62, p: 993 }, { c: 63, p: 997 }, { c: 64, p: 1000 }, { c: 65, p: 1000 } ],
    m2: [ { c: 0, p: 200 }, { c: 27, p: 600 }, { c: 55, p: 1000 } ],
    ciencias: [ { c: 0, p: 180 }, { c: 40, p: 650 }, { c: 80, p: 1000 } ],
    historia: [ { c: 0, p: 190 }, { c: 32, p: 620 }, { c: 65, p: 1000 } ],
};

// --- 3. Funciones "Helper" del Servidor ---
function sanitizeQuestions(questionData) {
    if (!questionData) return null;
    if (questionData.contexto) {
        const sanitizedPreguntas = questionData.preguntas.map(p => { const { correct, ...sanitizedP } = p; return sanitizedP; });
        return { ...questionData, preguntas: sanitizedPreguntas };
    } else {
        const { correct, ...sanitizedQ } = questionData; return sanitizedQ;
    }
}
function flattenQuestions(allQuestionData) { 
    if (allQuestionData.length > 0 && allQuestionData[0] && allQuestionData[0].contexto) {
        return allQuestionData.flatMap(item => item.preguntas.map(p => ({...p, context: item.contexto.texto})));
    } return allQuestionData;
}

// --- ¡FUNCIÓN DE CÁLCULO DE PUNTAJE CORREGIDA! ---
function calculateStandardScore(testKey, correctAnswers) {
    const table = scoreConversionTables[testKey];
    if (!table || table.length === 0) {
        return "N/A";
    }
    const exactMatch = table.find(item => item.c === correctAnswers);
    if (exactMatch) {
        return exactMatch.p;
    }
    const isFullTable = table.length > 10; 
    if (isFullTable) {
        let lower = { c: 0, p: 100 };
        let upper = { c: testDetails[testKey].questions, p: 1000 };
        for (const point of table) {
            if (point.c <= correctAnswers) {
                lower = point;
            }
            if (point.c >= correctAnswers) {
                upper = point;
                break;
            }
        }
        if (upper.c === lower.c) {
            return lower.p;
        }
        const percentage = (correctAnswers - lower.c) / (upper.c - lower.c);
        const score = Math.round(lower.p + percentage * (upper.p - lower.p));
        return score;
    } else {
        let finalScore = 100;
        for (const point of table) {
            if (point.c <= correctAnswers) {
                finalScore = point.p;
            } else {
                break;
            }
        }
        return finalScore;
    }
}


// --- 4. Configuración del servidor ---
const app = express();
const PORT = 3000;
app.use(cors());
app.use(express.json());

// --- 5. MIDDLEWARE DE AUTENTICACIÓN (ESTUDIANTES) ---
const authenticateSession = (req, res, next) => {
    const userId = req.headers['x-user-id'];
    const sessionId = req.headers['x-session-id'];
    const deviceToken = req.headers['x-device-token'];

    if (!userId || !sessionId || !deviceToken) {
        return res.status(401).json({ message: 'Acceso no autorizado: Faltan credenciales.' });
    }
    const user = users.find(u => u.id == userId);
    if (!user) {
        return res.status(401).json({ message: 'Usuario no encontrado.' });
    }
    if (user.deviceToken !== deviceToken) {
        return res.status(401).json({ message: 'Dispositivo no reconocido.' });
    }
    if (user.activeSessionId !== sessionId) {
        return res.status(401).json({ message: 'Sesión inválida o expirada. Inicie sesión nuevamente.' });
    }
    req.user = user;
    next();
};

// --- 6. ¡NUEVO MIDDLEWARE DE AUTENTICACIÓN (ADMIN)! ---
const authenticateAdmin = (req, res, next) => {
    const userId = req.headers['x-user-id'];
    const sessionId = req.headers['x-session-id'];

    if (!userId || !sessionId) {
        return res.status(401).json({ message: 'Acceso no autorizado: Faltan credenciales.' });
    }
    const user = users.find(u => u.id == userId);
    if (!user) {
        return res.status(401).json({ message: 'Usuario no encontrado.' });
    }
    if (user.activeSessionId !== sessionId) {
        return res.status(401).json({ message: 'Sesión inválida o expirada.' });
    }
    if (user.role !== 'admin') {
        return res.status(403).json({ message: 'Acceso denegado: Requiere permisos de administrador.' });
    }
    req.user = user;
    next();
};


// --- 7. Definir los "Endpoints" (las URLs) ---

app.get('/', (req, res) => {
    res.send('¡El servidor PAES 2026 está funcionando!');
});

// --- Endpoint para el LOGIN (¡ACTUALIZADO PARA MANEJAR ROLES!) ---
app.post('/api/login', (req, res) => {
    const { loginUser, loginPass, deviceToken } = req.body;
    const user = users.find(u => (u.user === loginUser || u.email === loginUser) && u.password === loginPass);

    if (!user) {
        return res.status(401).json({ message: 'Credenciales incorrectas.' });
    }

    // --- Lógica de Roles ---
    const userInDb = users.find(u => u.id === user.id);
    const newSessionId = crypto.randomBytes(16).toString('hex');
    userInDb.activeSessionId = newSessionId; // Actualiza la sesión para AMBOS roles

    const userResponse = { ...user };
    delete userResponse.password;

    // SI ES ADMIN:
    if (user.role === 'admin') {
        console.log(`Login de ADMIN exitoso para ${user.user}`);
        return res.json({ 
            user: userResponse, 
            sessionId: newSessionId,
            role: 'admin'
        });
    }

    // SI ES ESTUDIANTE (lógica existente):
    if (user.role === 'student') {
        const responseData = { 
            user: userResponse, 
            sessionId: newSessionId,
            role: 'student'
        };

        // Escenario 1: Primer login
        if (userInDb.deviceToken === null) {
            const newDeviceToken = crypto.randomBytes(16).toString('hex');
            userInDb.deviceToken = newDeviceToken;
            responseData.deviceToken = newDeviceToken;
            console.log(`Primer login para ${user.user}. Dispositivo registrado.`);
            return res.json(responseData);
        }

        // Escenario 2: Login subsecuente
        if (userInDb.deviceToken === deviceToken) {
            console.log(`Login exitoso para ${user.user} en dispositivo conocido.`);
            return res.json(responseData);
        }

        // Escenario 3: Dispositivo incorrecto
        console.warn(`Login RECHAZADO para ${user.user}. Dispositivo no coincide.`);
        return res.status(403).json({ message: 'Esta cuenta ya está registrada en otro dispositivo.' });
    }
    return res.status(403).json({ message: 'Rol de usuario no reconocido.' });
});

// --- 8. Endpoints de ESTUDIANTE (Protegidos por authenticateSession) ---
app.get('/api/session', authenticateSession, (req, res) => {
    const userResponse = { ...req.user };
    delete userResponse.password;
    delete userResponse.activeSessionId;
    res.json({ user: userResponse });
});

app.get('/api/questions', authenticateSession, (req, res) => {
    const sanitizedBanks = {};
    for (const testKey in questionBanks) {
        const originalQuestions = questionBanks[testKey] || [];
        sanitizedBanks[testKey] = originalQuestions.filter(Boolean).map(sanitizeQuestions);
    }
    res.json(sanitizedBanks);
});

// --- ¡NUEVO! Endpoint para el HISTORIAL DEL ESTUDIANTE ---
app.get('/api/student/history', authenticateSession, (req, res) => {
    // Busca en la BBDD de historial solo los de este usuario
    const userHistory = testHistory
        .filter(record => record.userId === req.user.id)
        .sort((a, b) => new Date(b.date) - new Date(a.date)) // Más nuevo primero
        .slice(0, 10); // Los últimos 10 como pediste
    
    res.json(userHistory);
});

app.post('/api/submit', authenticateSession, (req, res) => {
    try {
        const { testKey, userAnswers, questionsAnswered } = req.body;
        const allRealQuestions = questionBanks[testKey] || [];
        const flatRealQuestions = flattenQuestions(allRealQuestions);
        const answerMap = new Map();
        flatRealQuestions.forEach(q => { answerMap.set(q.question, q.correct); });
        
        let score = 0;
        const results = [];
        questionsAnswered.forEach((clientQ, index) => {
            const realCorrectIndex = answerMap.get(clientQ.question);
            const userAnswerIndex = userAnswers[index] ? parseInt(userAnswers[index]) : -1;
            const isCorrect = (realCorrectIndex === userAnswerIndex);
            if (isCorrect) score++;
            const realQuestion = flatRealQuestions.find(q => q.question === clientQ.question);
            if (realQuestion) {
                results.push({
                    question: clientQ,
                    userAnswerIndex: userAnswerIndex,
                    userAnswer: userAnswerIndex > -1 ? (clientQ.options[userAnswerIndex] || "No contestada") : "No contestada",
                    correctAnswer: realQuestion.options[realCorrectIndex],
                    isCorrect: isCorrect
                });
            }
        });

        const totalQuestions = questionsAnswered.length;
        const standardScore = calculateStandardScore(testKey, score);

        // --- ¡NUEVO! GUARDAR EL RESULTADO DE LA PRUEBA ---
        const historyRecord = {
            id: Date.now(),
            userId: req.user.id,
            userName: req.user.name,
            testKey: testKey,
            testName: testDetails[testKey].name,
            date: new Date().toISOString(),
            correctas: score,
            erroneas: totalQuestions - score,
            total: totalQuestions,
            puntaje: standardScore
        };
        testHistory.push(historyRecord);
        console.log(`Prueba guardada para ${req.user.user}: ${testKey}, Puntaje: ${standardScore}`);
        // --- FIN DE GUARDADO ---
        
        // Devolvemos el resultado al estudiante para la revisión
        res.json({
            score: score,
            total: totalQuestions,
            standardScore: standardScore,
            results: results
        });
    } catch (error) {
        console.error("Error al calificar la prueba:", error);
        res.status(500).json({ message: "Error interno del servidor al procesar la prueba." });
    }
});


// --- 9. ¡NUEVOS Endpoints de ADMIN (Protegidos por authenticateAdmin)! ---

// --- ¡NUEVO! Endpoint para ESTADÍSTICAS DEL ADMIN ---
app.get('/api/admin/stats', authenticateAdmin, (req, res) => {
    // 1. Últimos usuarios (basado en los últimos envíos de pruebas)
    const recentHistory = [...testHistory].sort((a, b) => new Date(b.date) - new Date(a.date));
    const lastUsers = [];
    const userIds = new Set();
    for (const record of recentHistory) {
        if (!userIds.has(record.userId) && lastUsers.length < 5) { // Últimos 5 usuarios únicos
            userIds.add(record.userId);
            lastUsers.push({ name: record.userName, date: record.date });
        }
    }

    // 2. KPIs por prueba
    const kpiByTest = {};
    for (const testKey in testDetails) {
        const tests = testHistory.filter(h => h.testKey === testKey);
        if (tests.length > 0) {
            const avgScore = tests.reduce((acc, t) => acc + t.puntaje, 0) / tests.length;
            const avgCorrectas = tests.reduce((acc, t) => acc + t.correctas, 0) / tests.length;
            kpiByTest[testKey] = {
                name: testDetails[testKey].name,
                intentos: tests.length,
                puntajePromedio: Math.round(avgScore),
                correctasPromedio: Math.round(avgCorrectas)
            };
        } else {
             kpiByTest[testKey] = {
                name: testDetails[testKey].name,
                intentos: 0,
                puntajePromedio: 0,
                correctasPromedio: 0
            };
        }
    }
    
    // 3. Devolver el objeto de estadísticas
    res.json({
        totalTestsTaken: testHistory.length,
        lastUsers: lastUsers,
        kpiByTest: kpiByTest
    });
});


// Endpoint para obtener la lista de usuarios
app.get('/api/admin/users', authenticateAdmin, (req, res) => {
    const safeUsers = users.map(u => {
        const { password, activeSessionId, ...safeUser } = u;
        return safeUser;
    });
    res.json(safeUsers);
});

// Endpoint para "liberar" el dispositivo de un estudiante
app.post('/api/admin/release-device/:id', authenticateAdmin, (req, res) => {
    const userIdToRelease = req.params.id;
    const student = users.find(u => u.id == userIdToRelease);

    if (!student) {
        return res.status(404).json({ message: 'Usuario no encontrado.' });
    }
    if (student.role !== 'student') {
        return res.status(400).json({ message: 'Solo se pueden liberar dispositivos de estudiantes.' });
    }

    student.deviceToken = null;
    student.activeSessionId = null; // También lo desconectamos
    
    console.log(`Admin ${req.user.user} liberó el dispositivo de ${student.user}`);
    
    // Devolvemos el usuario actualizado
    const { password, ...safeStudent } = student;
    res.json({ message: `Dispositivo del usuario ${student.user} liberado.`, user: safeStudent });
});

// --- ¡NUEVO! Endpoint para CREAR un usuario ---
app.post('/api/admin/users', authenticateAdmin, (req, res) => {
    const userData = req.body;
    
    if (!userData.user || !userData.name || !userData.email || !userData.password) {
        return res.status(400).json({ message: 'Usuario, nombre, email y contraseña son requeridos.' });
    }
    
    const newUser = {
        id: Date.now(),
        ...userData,
        role: userData.role || 'student', // Por defecto es estudiante
        deviceToken: null,
        activeSessionId: null,
        inProgressTests: {}
    };

    users.push(newUser);
    // (En una BBDD real, aquí guardarías en la BBDD)
    
    const { password, ...safeUser } = newUser;
    console.log(`Admin ${req.user.user} creó al usuario ${safeUser.user}`);
    res.status(201).json(safeUser);
});

// --- ¡NUEVO! Endpoint para ACTUALIZAR un usuario ---
app.put('/api/admin/users/:id', authenticateAdmin, (req, res) => {
    const userIdToUpdate = req.params.id;
    const updates = req.body;
    const userIndex = users.findIndex(u => u.id == userIdToUpdate);

    if (userIndex === -1) {
        return res.status(4404).json({ message: 'Usuario no encontrado.' });
    }

    // Actualiza el usuario
    const originalUser = users[userIndex];
    users[userIndex] = { ...originalUser, ...updates };

    // Si se envió una nueva contraseña, actualízala. Si no, mantén la original.
    if (updates.password) {
        users[userIndex].password = updates.password;
    } else {
        users[userIndex].password = originalUser.password;
    }
    
    console.log(`Admin ${req.user.user} actualizó al usuario ${users[userIndex].user}`);

    const { password, ...safeUser } = users[userIndex];
    res.json(safeUser);
});

// --- ¡NUEVO! Endpoint para ELIMINAR un usuario ---
app.delete('/api/admin/users/:id', authenticateAdmin, (req, res) => {
    const userIdToDelete = req.params.id;
    const userIndex = users.findIndex(u => u.id == userIdToDelete);

    if (userIndex === -1) {
        return res.status(404).json({ message: 'Usuario no encontrado.' });
    }
    
    if (users[userIndex].role === 'admin') {
         return res.status(403).json({ message: 'No se puede eliminar a un administrador.' });
    }

    const [deletedUser] = users.splice(userIndex, 1);
    console.log(`Admin ${req.user.user} eliminó al usuario ${deletedUser.user}`);

    res.status(200).json({ message: 'Usuario eliminado' });
});


// --- 10. Encender el servidor ---
app.listen(PORT, () => {
    console.log(`Servidor corriendo en http://localhost:${PORT}`);
});