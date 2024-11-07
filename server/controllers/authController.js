const Intern = require('../models/Intern');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library');
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

const verifyGoogleToken = async (token) => {
    const ticket = await client.verifyIdToken({
        idToken: token,
        audience: process.env.GOOGLE_CLIENT_ID,
    });
    return ticket.getPayload();
};

exports.signup = async (req, res) => {
    const { internID, firstName, lastName, email, password } = req.body;

    if (!email || !password || !firstName || !lastName || !internID) {
        return res.status(400).json({ message: 'All fields are required' });
    }

    const emailRegex = /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}$/;
    if (!emailRegex.test(email)) {
        return res.status(400).json({ message: 'Invalid email format' });
    }

    try {

        const hashedPassword = await bcrypt.hash(password, 10);

        const sanitizedInternID = String(internID).trim();

        const intern = new Intern({
            internID: sanitizedInternID,
            firstName: String(firstName).trim(),
            lastName: String(lastName).trim(),
            email: String(email).trim(),
            password: hashedPassword
        });

        await intern.save();
        res.status(201).json({ message: 'Intern registered successfully!' });
    } catch (error) {
        console.error('Error during signup:', error);
        res.status(500).json({ message: 'Internal server error during signup' });
    }
};

exports.login = async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: 'Email and password are required' });
    }

    try {
        const sanitizedEmail = String(email).trim();

        const intern = await Intern.findOne({ email: sanitizedEmail });

        if (!intern || !await bcrypt.compare(password, intern.password)) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        const token = jwt.sign({ id: intern._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ message: 'Internal server error during login' });
    }
};

exports.googleLogin = async (req, res) => {
    const { token } = req.body;

    try {
        const userData = await verifyGoogleToken(token);
        const { email } = userData;

        const sanitizedEmail = String(email).trim();

        let intern = await Intern.findOne({ email: sanitizedEmail });

        if (!intern) {
            return res.json({ isNewUser: true, email });
        }

        const jwtToken = jwt.sign({ id: intern._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ token: jwtToken, isNewUser: false });
    } catch (error) {
        console.error('Error during Google login:', error);
        res.status(500).json({ message: 'Google login failed' });
    }
};

exports.updateInternId = async (req, res) => {
    const { email, internId, firstName, lastName } = req.body;

    if (!email || !internId || !firstName || !lastName) {
        return res.status(400).json({ message: 'All fields are required' });
    }

    try {
        const sanitizedEmail = String(email).trim();
        const sanitizedInternId = String(internId).trim();

        let intern = await Intern.findOne({ email: sanitizedEmail });

        if (!intern) {
            intern = new Intern({
                email: sanitizedEmail,
                internID: sanitizedInternId,
                firstName: String(firstName).trim(),
                lastName: String(lastName).trim()
            });
            await intern.save();
        } else {
            intern.internID = sanitizedInternId;
            intern.firstName = String(firstName).trim();
            intern.lastName = String(lastName).trim();
            await intern.save();
        }

        const jwtToken = jwt.sign({ id: intern._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ token: jwtToken });
    } catch (error) {
        console.error('Failed to update Intern details:', error);
        res.status(500).json({ message: 'Failed to update intern details' });
    }
};
