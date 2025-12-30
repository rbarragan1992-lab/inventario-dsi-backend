import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { body, param, validationResult } from "express-validator";
import { pool } from "./db.js";

dotenv.config();
console.log("ENV CHECK -> DB_USER:", process.env.DB_USER);
console.log("ENV CHECK -> DB_PORT:", process.env.DB_PORT);
console.log("ENV CHECK -> DB_NAME:", process.env.DB_NAME);


const app = express();
app.use(cors());
app.use(express.json());

const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET || "change_this_secret";

// ---- Helpers ----
function validate(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  next();
}

function authRequired(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ message: "Missing token" });

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid token" });
  }
}

function adminOnly(req, res, next) {
  if (req.user?.role !== "admin") return res.status(403).json({ message: "Admin only" });
  next();
}

// ---- DB health check ----
app.get("/", async (_req, res) => {
  res.json({ ok: true, service: "Inventario API" });
});

app.get("/health/db", async (_req, res) => {
  try {
    const r = await pool.query("SELECT NOW() as now");
    res.json({ ok: true, now: r.rows[0].now });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

// ---- AUTH ----
app.post(
  "/auth/register",
  body("name").isString().isLength({ min: 2 }),
  body("email").isEmail(),
  body("password").isString().isLength({ min: 6 }),
  validate,
  async (req, res) => {
    const { name, email, password } = req.body;
    try {
      const existing = await pool.query("SELECT id FROM users WHERE email = $1", [email]);
      if (existing.rowCount) return res.status(409).json({ message: "Email already registered" });

      const password_hash = await bcrypt.hash(password, 10);
      const inserted = await pool.query(
        "INSERT INTO users(name,email,password_hash,role) VALUES($1,$2,$3,$4) RETURNING id,name,email,role,created_at",
        [name, email, password_hash, "user"]
      );

      res.status(201).json({ user: inserted.rows[0] });
    } catch (e) {
      res.status(500).json({ message: "Server error", error: String(e) });
    }
  }
);

app.post(
  "/auth/login",
  body("email").isEmail(),
  body("password").isString().isLength({ min: 1 }),
  validate,
  async (req, res) => {
    const { email, password } = req.body;
    try {
      const userRes = await pool.query("SELECT id,name,email,password_hash,role FROM users WHERE email = $1", [email]);
      if (!userRes.rowCount) return res.status(401).json({ message: "Invalid credentials" });

      const user = userRes.rows[0];
      const ok = await bcrypt.compare(password, user.password_hash);
      if (!ok) return res.status(401).json({ message: "Invalid credentials" });

      const token = jwt.sign({ id: user.id, email: user.email, role: user.role, name: user.name }, JWT_SECRET, {
        expiresIn: "8h",
      });

      res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
    } catch (e) {
      res.status(500).json({ message: "Server error", error: String(e) });
    }
  }
);

// ---- CATEGORIES ----
app.get("/categories", authRequired, async (_req, res) => {
  try {
    const r = await pool.query("SELECT id,name FROM categories ORDER BY name ASC");
    res.json(r.rows);
  } catch (e) {
    res.status(500).json({ message: "Server error", error: String(e) });
  }
});

app.post(
  "/categories",
  authRequired,
  adminOnly,
  body("name").isString().isLength({ min: 2 }),
  validate,
  async (req, res) => {
    const { name } = req.body;
    try {
      const r = await pool.query("INSERT INTO categories(name) VALUES($1) RETURNING id,name", [name.trim()]);
      res.status(201).json(r.rows[0]);
    } catch (e) {
      // unique violation
      if (String(e).includes("duplicate key")) return res.status(409).json({ message: "Category already exists" });
      res.status(500).json({ message: "Server error", error: String(e) });
    }
  }
);

// ---- PRODUCTS (CRUD) ----
app.get("/products", authRequired, async (_req, res) => {
  try {
    const r = await pool.query(
      `SELECT p.id,p.name,p.sku,p.price,p.stock,p.min_stock,p.created_at,
              c.id as category_id, c.name as category_name
       FROM products p
       LEFT JOIN categories c ON c.id = p.category_id
       ORDER BY p.id DESC`
    );
    res.json(r.rows);
  } catch (e) {
    res.status(500).json({ message: "Server error", error: String(e) });
  }
});

app.get(
  "/products/:id",
  authRequired,
  param("id").isInt(),
  validate,
  async (req, res) => {
    try {
      const r = await pool.query(
        `SELECT p.id,p.name,p.sku,p.price,p.stock,p.min_stock,p.created_at,
                c.id as category_id, c.name as category_name
         FROM products p
         LEFT JOIN categories c ON c.id = p.category_id
         WHERE p.id = $1`,
        [Number(req.params.id)]
      );
      if (!r.rowCount) return res.status(404).json({ message: "Not found" });
      res.json(r.rows[0]);
    } catch (e) {
      res.status(500).json({ message: "Server error", error: String(e) });
    }
  }
);

app.post(
  "/products",
  authRequired,
  adminOnly,
  body("name").isString().isLength({ min: 2 }),
  body("sku").isString().isLength({ min: 2 }),
  body("price").optional().isNumeric(),
  body("category_id").optional({ nullable: true }).isInt(),
  body("min_stock").optional().isInt({ min: 0 }),
  body("stock").optional().isInt({ min: 0 }),
  validate,
  async (req, res) => {
    const { name, sku, category_id = null, price = 0, stock = 0, min_stock = 0 } = req.body;
    try {
      const r = await pool.query(
        `INSERT INTO products(name,sku,category_id,price,stock,min_stock)
         VALUES($1,$2,$3,$4,$5,$6)
         RETURNING id,name,sku,category_id,price,stock,min_stock,created_at`,
        [name.trim(), sku.trim(), category_id ? Number(category_id) : null, Number(price), Number(stock), Number(min_stock)]
      );
      res.status(201).json(r.rows[0]);
    } catch (e) {
      if (String(e).includes("duplicate key")) return res.status(409).json({ message: "SKU already exists" });
      res.status(500).json({ message: "Server error", error: String(e) });
    }
  }
);

app.put(
  "/products/:id",
  authRequired,
  adminOnly,
  param("id").isInt(),
  body("name").optional().isString().isLength({ min: 2 }),
  body("sku").optional().isString().isLength({ min: 2 }),
  body("price").optional().isNumeric(),
  body("category_id").optional({ nullable: true }).isInt(),
  body("min_stock").optional().isInt({ min: 0 }),
  validate,
  async (req, res) => {
    const id = Number(req.params.id);
    const fields = ["name", "sku", "category_id", "price", "min_stock"];
    const sets = [];
    const values = [];
    let idx = 1;

    for (const f of fields) {
      if (f in req.body) {
        sets.push(`${f} = $${idx++}`);
        if (f === "category_id") values.push(req.body[f] ? Number(req.body[f]) : null);
        else if (f === "price") values.push(Number(req.body[f]));
        else if (f === "min_stock") values.push(Number(req.body[f]));
        else values.push(String(req.body[f]).trim());
      }
    }

    if (!sets.length) return res.status(400).json({ message: "No fields to update" });

    values.push(id);
    try {
      const q = `UPDATE products SET ${sets.join(", ")} WHERE id = $${idx} RETURNING *`;
      const r = await pool.query(q, values);
      if (!r.rowCount) return res.status(404).json({ message: "Not found" });
      res.json(r.rows[0]);
    } catch (e) {
      if (String(e).includes("duplicate key")) return res.status(409).json({ message: "SKU already exists" });
      res.status(500).json({ message: "Server error", error: String(e) });
    }
  }
);

app.delete(
  "/products/:id",
  authRequired,
  adminOnly,
  param("id").isInt(),
  validate,
  async (req, res) => {
    try {
      const r = await pool.query("DELETE FROM products WHERE id = $1 RETURNING id", [Number(req.params.id)]);
      if (!r.rowCount) return res.status(404).json({ message: "Not found" });
      res.json({ deleted: true, id: r.rows[0].id });
    } catch (e) {
      res.status(500).json({ message: "Server error", error: String(e) });
    }
  }
);

// ---- MOVEMENTS ----
app.get("/movements", authRequired, async (_req, res) => {
  try {
    const r = await pool.query(
      `SELECT m.id,m.type,m.quantity,m.note,m.created_at,
              p.id as product_id,p.name as product_name,p.sku as product_sku,
              u.id as user_id,u.name as user_name,u.email as user_email
       FROM movements m
       JOIN products p ON p.id = m.product_id
       LEFT JOIN users u ON u.id = m.user_id
       ORDER BY m.id DESC
       LIMIT 500`
    );
    res.json(r.rows);
  } catch (e) {
    res.status(500).json({ message: "Server error", error: String(e) });
  }
});

app.post(
  "/movements",
  authRequired,
  body("product_id").isInt(),
  body("type").isIn(["IN", "OUT"]),
  body("quantity").isInt({ min: 1 }),
  body("note").optional().isString(),
  validate,
  async (req, res) => {
    const { product_id, type, quantity, note = "" } = req.body;
    const pid = Number(product_id);
    const qty = Number(quantity);

    const client = await pool.connect();
    try {
      await client.query("BEGIN");

      const pr = await client.query("SELECT id, stock FROM products WHERE id = $1 FOR UPDATE", [pid]);
      if (!pr.rowCount) {
        await client.query("ROLLBACK");
        return res.status(404).json({ message: "Product not found" });
      }

      const currentStock = pr.rows[0].stock;
      let newStock = currentStock;

      if (type === "IN") newStock = currentStock + qty;
      if (type === "OUT") {
        if (currentStock < qty) {
          await client.query("ROLLBACK");
          return res.status(400).json({ message: "Not enough stock" });
        }
        newStock = currentStock - qty;
      }

      await client.query("UPDATE products SET stock = $1 WHERE id = $2", [newStock, pid]);

      const mr = await client.query(
        `INSERT INTO movements(product_id,user_id,type,quantity,note)
         VALUES($1,$2,$3,$4,$5)
         RETURNING id,product_id,user_id,type,quantity,note,created_at`,
        [pid, req.user.id, type, qty, note]
      );

      await client.query("COMMIT");
      res.status(201).json({ movement: mr.rows[0], stock: newStock });
    } catch (e) {
      await client.query("ROLLBACK");
      res.status(500).json({ message: "Server error", error: String(e) });
    } finally {
      client.release();
    }
  }
);

// ---- Seed admin (optional, dev) ----
app.post("/dev/seed-admin", async (_req, res) => {
  // Creates admin: admin@demo.com / admin123 (only if not exists)
  try {
    const email = "admin@demo.com";
    const existing = await pool.query("SELECT id FROM users WHERE email = $1", [email]);
    if (existing.rowCount) return res.json({ ok: true, message: "Admin already exists" });

    const password_hash = await bcrypt.hash("admin123", 10);
    const r = await pool.query(
      "INSERT INTO users(name,email,password_hash,role) VALUES($1,$2,$3,$4) RETURNING id,name,email,role",
      ["Admin Demo", email, password_hash, "admin"]
    );
    res.json({ ok: true, admin: r.rows[0], credentials: { email, password: "admin123" } });
  } catch (e) {
    res.status(500).json({ message: "Server error", error: String(e) });
  }
});

app.listen(PORT, () => {
  console.log(`Inventario API running on http://localhost:${PORT}`);
});
