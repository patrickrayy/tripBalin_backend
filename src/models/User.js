const pool = require('../config/database');
const bcrypt = require('bcrypt');

class User {
    static async findByEmail(email) {
        const [rows] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
        return rows[0];
    }

    static async create(userData) {
        const { name, email, password, tanggal_lahir, phone } = userData;
        const hashedPassword = await bcrypt.hash(password, 10);

        const [result] = await pool.query(
            'INSERT INTO users (name, email, password, role, tanggal_lahir, phone) VALUES (?, ?, ?, ?, ?, ?)',
            [name, email, hashedPassword, 'user', tanggal_lahir, phone]
        );

        return result.insertId;
    }

    static async findById(id) {
        const [rows] = await pool.query('SELECT id, name, email, role, tanggal_lahir, phone, created_at, updated_at FROM users WHERE id = ?', [id]);
        return rows[0];
    }

    static async updateProfile(id, userData) {
        const { name, tanggal_lahir, phone } = userData;
        const [result] = await pool.query(
            'UPDATE users SET name = ?, tanggal_lahir = ?, phone = ?, updated_at = NOW() WHERE id = ?',
            [name, tanggal_lahir, phone, id]
        );
        return result.affectedRows > 0;
    }
}

module.exports = User;