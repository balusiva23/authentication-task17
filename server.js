const express = require('express');
const app = express();
const authRoutes = require('./routes/auth');
const path = require('path'); // Add this line
require('./db/db'); // Connect to MongoDB

app.use(express.json()); // Parse JSON request bodies
app.use(express.urlencoded({ extended: true }));
// Set EJS as the view engine
app.set('view engine', 'ejs');

// Specify the directory where EJS templates are located
app.set('views', path.join(__dirname, 'views'));

// Use auth routes
app.use('/api/auth', authRoutes);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
