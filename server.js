// backend/server.js
const express = require('express');
const { google } = require('googleapis');
const { v4: uuidv4 } = require('uuid');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// Google Sheets Setup  
let credentialsPath;

// Verificar si existe la variable de entorno GOOGLE_CREDENTIALS
if (process.env.GOOGLE_CREDENTIALS) {
  console.log('📋 Usando GOOGLE_CREDENTIALS desde variable de entorno');
  
  // Crear el archivo credentials.json temporalmente desde la variable de entorno
  credentialsPath = path.join(__dirname, 'credentials.json');
  
  try {
    // Parsear y escribir el JSON
    const credentials = JSON.parse(process.env.GOOGLE_CREDENTIALS);
    fs.writeFileSync(credentialsPath, JSON.stringify(credentials, null, 2));
    console.log('✅ Archivo credentials.json creado exitosamente');
  } catch (error) {
    console.error('❌ Error al procesar GOOGLE_CREDENTIALS:', error.message);
    process.exit(1);
  }
} else {
  console.log('📁 Usando archivo credentials.json local');
  credentialsPath = path.join(__dirname, 'credentials.json');
  
  // Verificar que el archivo existe en desarrollo
  if (!fs.existsSync(credentialsPath)) {
    console.error('❌ ERROR: No se encontró credentials.json y tampoco existe la variable GOOGLE_CREDENTIALS');
    console.error('💡 Solución: Agrega la variable de entorno GOOGLE_CREDENTIALS en Railway');
    process.exit(1);
  }
}

const auth = new google.auth.GoogleAuth({
  keyFile: credentialsPath,
  scopes: ['https://www.googleapis.com/auth/spreadsheets'],
});

const sheets = google.sheets({ version: 'v4', auth });

// ========================================
// USER DATABASE (archivo JSON simple)
// ========================================

const USERS_FILE = path.join(__dirname, 'users.json');

// Inicializar archivo de usuarios si no existe
if (!fs.existsSync(USERS_FILE)) {
  fs.writeFileSync(USERS_FILE, JSON.stringify([], null, 2));
}

function getUsers() {
  const data = fs.readFileSync(USERS_FILE, 'utf8');
  return JSON.parse(data);
}

function saveUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

function findUserByEmail(email) {
  const users = getUsers();
  return users.find(u => u.email === email);
}

function findUserByToken(token) {
  const users = getUsers();
  return users.find(u => u.token === token);
}

// ========================================
// AUTHENTICATION MIDDLEWARE
// ========================================

const authenticateUser = (req, res, next) => {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, error: 'No autorizado' });
  }
  
  const token = authHeader.replace('Bearer ', '');
  const user = findUserByToken(token);
  
  if (!user) {
    return res.status(401).json({ success: false, error: 'Token inválido' });
  }
  
  req.user = user;
  next();
};

// ========================================
// HELPERS
// ========================================

const rowToTransaction = (row) => {
  if (!row || row.length === 0) return null;
  
  return {
    id: row[0] || '',
    user_id: row[1] || '',
    type: row[2] || '',
    concept: row[3] || '',
    amount: parseFloat(row[4]) || 0,
    currency: row[5] || 'EUR',
    category: row[6] || '',
    subcategory: row[7] || null,
    date: row[8] || '',
    created_at: row[9] || '',
    updated_at: row[10] || '',
  };
};

const transactionToRow = (transaction) => [
  transaction.id,
  transaction.user_id,
  transaction.type,
  transaction.concept,
  transaction.amount,
  transaction.currency,
  transaction.category,
  transaction.subcategory || '',
  transaction.date,
  transaction.created_at,
  transaction.updated_at,
];

const getAllTransactions = async (sheetId) => {
  try {
    const response = await sheets.spreadsheets.values.get({
      spreadsheetId: sheetId,
      range: 'transactions!A2:K',
    });

    const rows = response.data.values || [];
    return rows.map(rowToTransaction).filter(t => t !== null);
  } catch (error) {
    console.error('Error al obtener transacciones:', error);
    return [];
  }
};

const findRowIndexById = async (sheetId, id) => {
  const transactions = await getAllTransactions(sheetId);
  const index = transactions.findIndex(t => t.id === id);
  return index >= 0 ? index + 2 : -1;
};

// ========================================
// AUTH ENDPOINTS
// ========================================

// REGISTER
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password, sheetId } = req.body;
    
    // Validaciones
    if (!name || !email || !password || !sheetId) {
      return res.status(400).json({ 
        success: false, 
        error: 'Todos los campos son obligatorios' 
      });
    }
    
    if (password.length < 6) {
      return res.status(400).json({ 
        success: false, 
        error: 'La contraseña debe tener al menos 6 caracteres' 
      });
    }
    
    // Verificar si el usuario ya existe
    const existingUser = findUserByEmail(email);
    if (existingUser) {
      return res.status(400).json({ 
        success: false, 
        error: 'El email ya está registrado' 
      });
    }
    
    // Verificar que el Google Sheet existe y es accesible
    try {
      await sheets.spreadsheets.get({
        spreadsheetId: sheetId,
      });
    } catch (error) {
      return res.status(400).json({ 
        success: false, 
        error: 'No se puede acceder al Google Sheet. Verifica el ID y los permisos.' 
      });
    }
    
    // Crear nuevo usuario
    const newUser = {
      id: uuidv4(),
      name: name.trim(),
      email: email.toLowerCase().trim(),
      password, // En producción: usar bcrypt para hashear
      sheetId: sheetId.trim(),
      token: uuidv4(),
      createdAt: new Date().toISOString(),
    };
    
    const users = getUsers();
    users.push(newUser);
    saveUsers(users);
    
    console.log('✅ Usuario registrado:', newUser.email);
    
    res.status(201).json({ 
      success: true, 
      message: 'Usuario creado exitosamente' 
    });
    
  } catch (error) {
    console.error('❌ Error en registro:', error);
    res.status(500).json({ 
      success: false, 
      error: error.message 
    });
  }
});

// LOGIN
app.post('/api/auth/login', (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ 
        success: false, 
        error: 'Email y contraseña son obligatorios' 
      });
    }
    
    const user = findUserByEmail(email.toLowerCase().trim());
    
    if (!user || user.password !== password) {
      return res.status(401).json({ 
        success: false, 
        error: 'Credenciales incorrectas' 
      });
    }
    
    console.log('✅ Usuario autenticado:', user.email);
    
    res.json({ 
      success: true, 
      token: user.token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
      }
    });
    
  } catch (error) {
    console.error('❌ Error en login:', error);
    res.status(500).json({ 
      success: false, 
      error: error.message 
    });
  }
});

// ========================================
// TRANSACTION ENDPOINTS (PROTECTED)
// ========================================

// Health Check (no requiere auth)
app.get('/api/health', (req, res) => {
  res.json({ 
    success: true, 
    message: 'API funcionando correctamente',
    timestamp: new Date().toISOString()
  });
});

// CREATE
app.post('/api/transactions', authenticateUser, async (req, res) => {
  try {
    const { type, concept, amount, currency, category, subcategory, date } = req.body;
    const sheetId = req.user.sheetId;

    // Validaciones
    if (!type || !['gasto', 'ingreso'].includes(type.toLowerCase())) {
      return res.status(400).json({ 
        success: false, 
        error: 'El tipo debe ser "gasto" o "ingreso"' 
      });
    }

    if (!concept || concept.trim() === '') {
      return res.status(400).json({ 
        success: false, 
        error: 'El concepto es obligatorio' 
      });
    }

    if (!amount || amount <= 0) {
      return res.status(400).json({ 
        success: false, 
        error: 'La cantidad debe ser mayor a 0' 
      });
    }

    if (!category) {
      return res.status(400).json({ 
        success: false, 
        error: 'La categoría es obligatoria' 
      });
    }

    const transaction = {
      id: uuidv4(),
      user_id: req.user.email, // Email como user_id
      type: type.toLowerCase(),
      concept: concept.trim(),
      amount: parseFloat(amount),
      currency: currency || 'EUR',
      category: category.toLowerCase(),
      subcategory: subcategory ? subcategory.trim() : null,
      date: date || new Date().toISOString().split('T')[0],
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };

    await sheets.spreadsheets.values.append({
      spreadsheetId: sheetId,
      range: 'transactions!A:K',
      valueInputOption: 'USER_ENTERED',
      resource: {
        values: [transactionToRow(transaction)],
      },
    });

    console.log('✅ Transacción creada:', transaction.id, 'Usuario:', req.user.email);
    res.status(201).json({ success: true, transaction });

  } catch (error) {
    console.error('❌ Error al crear transacción:', error);
    res.status(500).json({ 
      success: false, 
      error: error.message 
    });
  }
});

// READ ALL
app.get('/api/transactions', authenticateUser, async (req, res) => {
  try {
    const sheetId = req.user.sheetId;
    let transactions = await getAllTransactions(sheetId);

    if (req.query.month) {
      const monthPrefix = req.query.month;
      transactions = transactions.filter(t => t.date.startsWith(monthPrefix));
    }

    transactions.sort((a, b) => new Date(b.date) - new Date(a.date));

    const limit = parseInt(req.query.limit) || transactions.length;
    const limitedTransactions = transactions.slice(0, limit);

    res.json({ 
      success: true, 
      transactions: limitedTransactions, 
      total: limitedTransactions.length 
    });

  } catch (error) {
    console.error('❌ Error al listar transacciones:', error);
    res.status(500).json({ 
      success: false, 
      error: error.message 
    });
  }
});

// READ ONE
app.get('/api/transactions/:id', authenticateUser, async (req, res) => {
  try {
    const sheetId = req.user.sheetId;
    const transactions = await getAllTransactions(sheetId);
    const transaction = transactions.find(t => t.id === req.params.id);

    if (!transaction) {
      return res.status(404).json({ 
        success: false, 
        error: 'Transacción no encontrada' 
      });
    }

    res.json({ success: true, transaction });

  } catch (error) {
    console.error('❌ Error al obtener transacción:', error);
    res.status(500).json({ 
      success: false, 
      error: error.message 
    });
  }
});

// UPDATE
app.put('/api/transactions/:id', authenticateUser, async (req, res) => {
  try {
    const sheetId = req.user.sheetId;
    const rowIndex = await findRowIndexById(sheetId, req.params.id);

    if (rowIndex === -1) {
      return res.status(404).json({ 
        success: false, 
        error: 'Transacción no encontrada' 
      });
    }

    const transactions = await getAllTransactions(sheetId);
    const currentTransaction = transactions.find(t => t.id === req.params.id);

    const updatedTransaction = {
      ...currentTransaction,
      ...req.body,
      id: currentTransaction.id,
      user_id: currentTransaction.user_id,
      updated_at: new Date().toISOString(),
    };

    await sheets.spreadsheets.values.update({
      spreadsheetId: sheetId,
      range: `transactions!A${rowIndex}:K${rowIndex}`,
      valueInputOption: 'USER_ENTERED',
      resource: {
        values: [transactionToRow(updatedTransaction)],
      },
    });

    console.log('✅ Transacción actualizada:', updatedTransaction.id);
    res.json({ success: true, transaction: updatedTransaction });

  } catch (error) {
    console.error('❌ Error al actualizar transacción:', error);
    res.status(500).json({ 
      success: false, 
      error: error.message 
    });
  }
});

// DELETE
app.delete('/api/transactions/:id', authenticateUser, async (req, res) => {
  try {
    const sheetId = req.user.sheetId;
    const rowIndex = await findRowIndexById(sheetId, req.params.id);

    if (rowIndex === -1) {
      return res.status(404).json({ 
        success: false, 
        error: 'Transacción no encontrada' 
      });
    }

    await sheets.spreadsheets.batchUpdate({
      spreadsheetId: sheetId,
      resource: {
        requests: [
          {
            deleteDimension: {
              range: {
                sheetId: 0,
                dimension: 'ROWS',
                startIndex: rowIndex - 1,
                endIndex: rowIndex,
              },
            },
          },
        ],
      },
    });

    console.log('✅ Transacción eliminada:', req.params.id);
    res.json({ 
      success: true, 
      message: 'Transacción eliminada correctamente' 
    });

  } catch (error) {
    console.error('❌ Error al eliminar transacción:', error);
    res.status(500).json({ 
      success: false, 
      error: error.message 
    });
  }
});

// REPORT
app.get('/api/reports/monthly', authenticateUser, async (req, res) => {
  try {
    const sheetId = req.user.sheetId;
    const month = req.query.month;

    if (!month) {
      return res.status(400).json({ 
        success: false, 
        error: 'Debes proporcionar el parámetro "month" (formato: 2025-01)' 
      });
    }

    const transactions = await getAllTransactions(sheetId);
    const monthTransactions = transactions.filter(t => t.date.startsWith(month));

    const gastos = monthTransactions.filter(t => t.type === 'gasto');
    const ingresos = monthTransactions.filter(t => t.type === 'ingreso');

    const total_gastos = gastos.reduce((sum, t) => sum + t.amount, 0);
    const total_ingresos = ingresos.reduce((sum, t) => sum + t.amount, 0);

    const gastos_por_categoria = gastos.reduce((acc, t) => {
      acc[t.category] = (acc[t.category] || 0) + t.amount;
      return acc;
    }, {});

    res.json({
      success: true,
      month,
      total_gastos: parseFloat(total_gastos.toFixed(2)),
      total_ingresos: parseFloat(total_ingresos.toFixed(2)),
      balance: parseFloat((total_ingresos - total_gastos).toFixed(2)),
      gastos_por_categoria,
      num_transacciones: monthTransactions.length,
    });

  } catch (error) {
    console.error('❌ Error al generar reporte:', error);
    res.status(500).json({ 
      success: false, 
      error: error.message 
    });
  }
});

// ========================================
// START SERVER
// ========================================

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`
╔════════════════════════════════════════╗
║   🚀 FinanzApp API Server v2.0         ║
║   📡 Puerto: ${PORT}                      ║
║   🌐 http://localhost:${PORT}            ║
║   🔐 Multi-usuario habilitado          ║
╚════════════════════════════════════════╝
  `);
});