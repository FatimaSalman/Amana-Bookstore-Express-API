const express = require('express');
const fs = require('fs');
const path = require('path');
const morgan = require('morgan');

const app = express();
const PORT = process.env.PORT || 3000;

// ============================================================================
// MORGAN LOGGING MIDDLEWARE
// ============================================================================

// Create a write stream for logging (in append mode)
const logStream = fs.createWriteStream(path.join(__dirname, 'log.txt'), { flags: 'a' });

// Custom token for logging user info if available
morgan.token('user', (req) => {
    return req.user ? req.user.username : 'anonymous';
});

// Custom token for logging API key (masked for security)
morgan.token('apikey', (req) => {
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
        const apiKey = authHeader.substring(7);
        return apiKey.substring(0, 8) + '...'; // Only log first 8 chars for security
    }
    return 'none';
});

// Custom format for logging
const logFormat = ':remote-addr - :user [:date[clf]] ":method :url HTTP/:http-version" :status :res[content-length] ":referrer" ":user-agent" - APIKey::apikey';

// Use Morgan middleware with custom format
app.use(morgan(logFormat, {
    stream: logStream,
    // Also log to console in development
    skip: (req, res) => process.env.NODE_ENV === 'production' && req.url === '/health'
}));

// Also log to console in development mode
if (process.env.NODE_ENV !== 'production') {
    app.use(morgan('dev'));
}

// Middleware to parse JSON
app.use(express.json());

// ============================================================================
// AUTHENTICATION MIDDLEWARE
// ============================================================================

// Simple in-memory user store (in production, use a database)
const authorizedUsers = {
    'admin': {
        password: 'bookstore2024', // In production, use hashed passwords
        role: 'admin',
        apiKey: 'amana-admin-key-2024'
    },
    'publisher': {
        password: 'publish123',
        role: 'publisher',
        apiKey: 'amana-publisher-key-2024'
    },
    'reviewer': {
        password: 'review456',
        role: 'reviewer',
        apiKey: 'amana-reviewer-key-2024'
    }
};

// Generate API keys (run once and use the generated keys)
const generateAPIKeys = () => {
    Object.keys(authorizedUsers).forEach(user => {
        authorizedUsers[user].apiKey = crypto.randomBytes(32).toString('hex');
    });
    console.log('Generated API Keys:', authorizedUsers);
};

// Uncomment the line below to generate new API keys
// generateAPIKeys();

// Authentication Middleware
const authenticate = (req, res, next) => {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({
            success: false,
            message: 'Access denied. No API key provided.',
            hint: 'Include: Authorization: Bearer your-api-key'
        });
    }

    const apiKey = authHeader.substring(7); // Remove "Bearer " prefix

    // Find user by API key
    const user = Object.entries(authorizedUsers).find(([username, data]) => data.apiKey === apiKey);

    if (!user) {
        return res.status(401).json({
            success: false,
            message: 'Invalid API key',
            hint: 'Check your API key or contact administrator'
        });
    }

    // Attach user info to request
    req.user = {
        username: user[0],
        role: user[1].role
    };

    next();
};

// Role-based authorization middleware
const requireRole = (roles) => {
    return (req, res, next) => {
        if (!roles.includes(req.user.role)) {
            return res.status(403).json({
                success: false,
                message: `Access denied. Required roles: ${roles.join(', ')}`,
                yourRole: req.user.role
            });
        }
        next();
    };
}

// Helper function to read books data
const readBooksData = () => {
    try {
        const booksPath = path.join(__dirname, 'data', 'books.json');
        const booksData = fs.readFileSync(booksPath, 'utf8');
        const data = JSON.parse(booksData);
        if (Array.isArray(data)) {
            return { books: data };
        } else if (data && typeof data === 'object' && data.books) {
            return data;
        } else {
            return { books: [] };
        }
    } catch (error) {
        console.error('Error reading books data:', error);
        return { books: [] };
    }
};

// Helper function to read reviews data
const readReviewsData = () => {
    try {
        const reviewsPath = path.join(__dirname, 'data', 'reviews.json');
        const reviewsData = fs.readFileSync(reviewsPath, 'utf8');
        const data = JSON.parse(reviewsData);
        if (Array.isArray(data)) {
            return { reviews: data };
        } else if (data && typeof data === 'object' && data.reviews) {
            return data;
        } else {
            return { reviews: [] };
        }
    } catch (error) {
        console.error('Error reading reviews data:', error);
        return { reviews: [] };
    }
};

// Validation function for date format (YYYY-MM-DD)
const isValidDate = (dateString) => {
    const regex = /^\d{4}-\d{2}-\d{2}$/;
    if (!dateString.match(regex)) return false;

    const date = new Date(dateString);
    const timestamp = date.getTime();

    if (typeof timestamp !== 'number' || Number.isNaN(timestamp)) {
        return false;
    }

    return date.toISOString().startsWith(dateString);
};

// Helper function to write reviews data
const writeBooksData = (data) => {
    try {
        const reviewsPath = path.join(__dirname, 'data', 'books.json');
        fs.writeFileSync(reviewsPath, JSON.stringify(data, null, 2));
        return true;
    } catch (error) {
        console.error('Error writing reviews data:', error);
        return false;
    }
};

// Helper function to write reviews data
const writeReviewsData = (data) => {
    try {
        const reviewsPath = path.join(__dirname, 'data', 'reviews.json');
        fs.writeFileSync(reviewsPath, JSON.stringify(data, null, 2));
        return true;
    } catch (error) {
        console.error('Error writing reviews data:', error);
        return false;
    }
};

// POST /api/books - Add a new book to the catalogue
app.post('/api/books', authenticate, requireRole(['admin', 'publisher']), (req, res) => {
    try {
        const {
            title,
            author,
            description,
            price,
            image = "/images/default-book.jpg",
            isbn,
            genre = [],
            tags = [],
            datePublished,
            pages,
            language = "English",
            publisher,
            rating = 0,
            reviewCount = 0,
            inStock = true,
            featured = false
        } = req.body;

        // Validation
        if (!title || !author || !description || !price || !isbn || !publisher) {
            return res.status(400).json({
                success: false,
                message: 'Missing required fields',
                required: ['title', 'author', 'description', 'price', 'isbn', 'publisher']
            });
        }

        if (typeof price !== 'number' || price <= 0) {
            return res.status(400).json({
                success: false,
                message: 'Price must be a positive number'
            });
        }

        if (datePublished && !isValidDate(datePublished)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid datePublished format. Use YYYY-MM-DD'
            });
        }

        // Read existing data
        const data = readBooksData();

        // Check if ISBN already exists
        const existingBook = data.books.find(book => book.isbn === isbn);
        if (existingBook) {
            return res.status(409).json({
                success: false,
                message: 'Book with this ISBN already exists',
                existingBook: {
                    id: existingBook.id,
                    title: existingBook.title,
                    author: existingBook.author
                }
            });
        }

        // Generate new book ID
        const newId = (Math.max(...data.books.map(book => parseInt(book.id))) + 1).toString();

        // Create new book object
        const newBook = {
            id: newId,
            title,
            author,
            description,
            price: parseFloat(price.toFixed(2)),
            image,
            isbn,
            genre: Array.isArray(genre) ? genre : [genre],
            tags: Array.isArray(tags) ? tags : [tags],
            datePublished: datePublished || new Date().toISOString().split('T')[0],
            pages: pages ? parseInt(pages) : undefined,
            language,
            publisher,
            rating: parseFloat(rating.toFixed(1)),
            reviewCount: parseInt(reviewCount),
            inStock: Boolean(inStock),
            featured: Boolean(featured),
            createdAt: new Date().toISOString(),
            createdBy: req.user.username
        };

        // Add to data
        data.books.push(newBook);

        // Write to file
        if (!writeBooksData(data)) {
            return res.status(500).json({
                success: false,
                message: 'Error saving book to catalogue'
            });
        }

        res.status(201).json({
            success: true,
            message: 'Book added successfully',
            data: newBook,
            addedBy: req.user.username
        });

    } catch (error) {
        console.error('Error adding book:', error);
        res.status(500).json({
            success: false,
            message: 'Error adding book to catalogue',
            error: error.message
        });
    }
});

// POST /api/reviews - Add a new review
app.post('/api/reviews', authenticate, requireRole(['admin', 'reviewer']), (req, res) => {
    try {
        const {
            bookId,
            author,
            rating,
            title,
            comment,
            verified = false
        } = req.body;

        // Validation
        if (!bookId || !author || !rating || !title || !comment) {
            return res.status(400).json({
                success: false,
                message: 'Missing required fields',
                required: ['bookId', 'author', 'rating', 'title', 'comment']
            });
        }

        if (typeof rating !== 'number' || rating < 1 || rating > 5) {
            return res.status(400).json({
                success: false,
                message: 'Rating must be a number between 1 and 5'
            });
        }

        // Check if book exists
        const booksData = readBooksData();
        const book = booksData.books.find(b => b.id === bookId);
        if (!book) {
            return res.status(404).json({
                success: false,
                message: `Book not found with ID: ${bookId}`,
                suggestedIds: booksData.books.map(b => b.id)
            });
        }

        // Read existing reviews
        const reviewsData = readReviewsData();

        // Generate new review ID
        // Generate sequential review ID in format "review-10"
        let newReviewId;
        let reviewNumber = 1;
        let idExists = true;

        // Find the next available sequential ID
        while (idExists) {
            newReviewId = `review-${reviewNumber}`;
            // Check if this ID already exists
            const existingReview = reviewsData.reviews.find(review => review.id === newReviewId);
            if (!existingReview) {
                idExists = false; // Found available ID
            } else {
                reviewNumber++; // Try next number
            }

            // Safety check to prevent infinite loop
            if (reviewNumber > 1000) {
                return res.status(500).json({
                    success: false,
                    message: 'Unable to generate unique review ID'
                });
            }
        }

        // Create new review object
        const newReview = {
            id: newReviewId,
            bookId,
            author,
            rating: parseInt(rating),
            title,
            comment,
            timestamp: new Date().toISOString(),
            verified: Boolean(verified),
            submittedBy: req.user.username
        };

        // Add to reviews data
        reviewsData.reviews.push(newReview);

        // Update book's review count and rating
        const bookReviews = reviewsData.reviews.filter(review => review.bookId === bookId);
        const averageRating = bookReviews.reduce((sum, review) => sum + review.rating, 0) / bookReviews.length;

        book.rating = parseFloat(averageRating.toFixed(1));
        book.reviewCount = bookReviews.length;

        // Write both files
        if (!writeReviewsData(reviewsData) || !writeBooksData(booksData)) {
            return res.status(500).json({
                success: false,
                message: 'Error saving review'
            });
        }

        res.status(201).json({
            success: true,
            message: 'Review added successfully',
            data: newReview,
            bookUpdate: {
                newRating: book.rating,
                newReviewCount: book.reviewCount
            },
            submittedBy: req.user.username
        });

    } catch (error) {
        console.error('Error adding review:', error);
        res.status(500).json({
            success: false,
            message: 'Error adding review',
            error: error.message
        });
    }
});

// ============================================================================
// AUTHENTICATION ROUTES (For getting API keys)
// ============================================================================

// POST /api/auth/login - Login to get API key (for testing)
app.post('/api/auth/login', (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({
                success: false,
                message: 'Username and password required'
            });
        }

        const user = authorizedUsers[username];

        if (!user || user.password !== password) {
            return res.status(401).json({
                success: false,
                message: 'Invalid credentials'
            });
        }

        res.status(200).json({
            success: true,
            message: 'Login successful',
            user: {
                username,
                role: user.role,
                apiKey: user.apiKey
            },
            instructions: 'Use this API key in the Authorization header: Bearer your-api-key'
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({
            success: false,
            message: 'Login failed',
            error: error.message
        });
    }
});

// GET /api/auth/users - List available users (for testing)
app.get('/api/auth/users', (req, res) => {
    const users = Object.keys(authorizedUsers).map(username => ({
        username,
        role: authorizedUsers[username].role,
        // Don't expose passwords in real application
        hasPassword: !!authorizedUsers[username].password
    }));

    res.json({
        success: true,
        data: users,
        note: 'Use POST /api/auth/login to get API keys'
    });
});

// ============================================================================
// ROUTE 1: GET /api/books - Display all books in the catalogue
// ============================================================================
app.get('/api/books', (req, res) => {
    try {
        const data = readBooksData();

        res.status(200).json({
            success: true,
            count: data.books.length,
            data: data.books
        });
    } catch (error) {
        console.error('Error fetching books:', error);
        res.status(500).json({
            success: false,
            message: 'Error fetching books from catalogue',
            error: error.message
        });
    }
});

// ============================================================================
// ROUTE 5: GET /api/books/featured - Books with featured tag set to true
// ============================================================================
app.get('/api/books/featured', (req, res) => {
    try {

        const data = readBooksData();

        // Filter featured books
        const featuredBooks = data.books.filter(book => book.featured === true);

        res.status(200).json({
            success: true,
            count: featuredBooks.length,
            data: featuredBooks
        });

    } catch (error) {
        console.error('Error fetching featured books:', error);
        res.status(500).json({
            success: false,
            message: 'Error fetching featured books',
            error: error.message
        });
    }
});

// ============================================================================
// ROUTE 3: GET /api/books/published - Books published between date range
// ============================================================================
app.get('/api/books/published', (req, res) => {
    try {
        const { startDate, endDate, sort = 'date_desc' } = req.query;
        const data = readBooksData();

        // Validate date parameters
        if (!startDate || !endDate) {
            return res.status(400).json({
                success: false,
                message: 'Both startDate and endDate query parameters are required',
                example: '/api/books/published?startDate=2022-01-01&endDate=2023-12-31'
            });
        }

        if (!isValidDate(startDate)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid startDate format. Use YYYY-MM-DD',
                received: startDate,
                example: '2022-01-01'
            });
        }

        if (!isValidDate(endDate)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid endDate format. Use YYYY-MM-DD',
                received: endDate,
                example: '2023-12-31'
            });
        }

        const start = new Date(startDate);
        const end = new Date(endDate);

        if (end < start) {
            return res.status(400).json({
                success: false,
                message: 'endDate must be after or equal to startDate',
                startDate,
                endDate
            });
        }

        // Filter books by publication date range
        const filteredBooks = data.books.filter(book => {
            const bookDate = new Date(book.datePublished);
            return bookDate >= start && bookDate <= end;
        });

        // Sort the results
        let sortedBooks = [...filteredBooks];
        switch (sort) {
            case 'date_asc':
                sortedBooks.sort((a, b) => new Date(a.datePublished) - new Date(b.datePublished));
                break;
            case 'date_desc':
                sortedBooks.sort((a, b) => new Date(b.datePublished) - new Date(a.datePublished));
                break;
            case 'title_asc':
                sortedBooks.sort((a, b) => a.title.localeCompare(b.title));
                break;
            case 'title_desc':
                sortedBooks.sort((a, b) => b.title.localeCompare(a.title));
                break;
            case 'price_asc':
                sortedBooks.sort((a, b) => a.price - b.price);
                break;
            case 'price_desc':
                sortedBooks.sort((a, b) => b.price - a.price);
                break;
            case 'rating_desc':
                sortedBooks.sort((a, b) => b.rating - a.rating);
                break;
        }

        // Calculate date range statistics
        const dateStats = {
            totalBooksInRange: sortedBooks.length,
            dateRange: {
                start: startDate,
                end: endDate,
                daysInRange: Math.ceil((end - start) / (1000 * 60 * 60 * 24)) + 1
            },
            publicationYears: [...new Set(sortedBooks.map(book => new Date(book.datePublished).getFullYear()))],
            publishers: [...new Set(sortedBooks.map(book => book.publisher))]
        };

        res.status(200).json({
            success: true,
            statistics: dateStats,
            count: sortedBooks.length,
            data: sortedBooks
        });

    } catch (error) {
        console.error('Error fetching books by date range:', error);
        res.status(500).json({
            success: false,
            message: 'Error fetching books by publication date',
            error: error.message
        });
    }
});

// ============================================================================
// ROUTE 4: GET /api/books/top-rated - Top 10 rated books (rating * reviewCount)
// ============================================================================
app.get('/api/books/top-rated', (req, res) => {
    try {
        const { limit = 10, minReviews = 0 } = req.query;
        const data = readBooksData();

        const limitCount = parseInt(limit);
        const minReviewsCount = parseInt(minReviews);

        // Validate parameters
        if (isNaN(limitCount) || limitCount < 1 || limitCount > 50) {
            return res.status(400).json({
                success: false,
                message: 'Limit must be a number between 1 and 50',
                received: limit
            });
        }

        if (isNaN(minReviewsCount) || minReviewsCount < 0) {
            return res.status(400).json({
                success: false,
                message: 'minReviews must be a positive number',
                received: minReviews
            });
        }

        // Filter books by minimum reviews if specified
        let filteredBooks = data.books;
        if (minReviewsCount > 0) {
            filteredBooks = data.books.filter(book => book.reviewCount >= minReviewsCount);
        }

        // Calculate weighted scores (rating * reviewCount)
        const booksWithScores = filteredBooks.map(book => ({
            ...book,
            weightedScore: book.rating * book.reviewCount,
            scoreExplanation: `Rating (${book.rating}) × Reviews (${book.reviewCount}) = ${(book.rating * book.reviewCount).toFixed(1)}`
        }));

        // Sort by weighted score (descending)
        const sortedBooks = booksWithScores.sort((a, b) => b.weightedScore - a.weightedScore);

        // Take top N books
        const topBooks = sortedBooks.slice(0, limitCount);

        // Calculate statistics
        const stats = {
            totalBooksConsidered: filteredBooks.length,
            algorithm: 'rating × reviewCount',
            minimumReviews: minReviewsCount,
            averageRating: filteredBooks.reduce((sum, book) => sum + book.rating, 0) / filteredBooks.length,
            averageReviews: filteredBooks.reduce((sum, book) => sum + book.reviewCount, 0) / filteredBooks.length,
            scoreRange: {
                min: Math.min(...booksWithScores.map(book => book.weightedScore)),
                max: Math.max(...booksWithScores.map(book => book.weightedScore))
            }
        };

        res.status(200).json({
            success: true,
            statistics: stats,
            count: topBooks.length,
            data: topBooks
        });

    } catch (error) {
        console.error('Error fetching top rated books:', error);
        res.status(500).json({
            success: false,
            message: 'Error fetching top rated books',
            error: error.message
        });
    }
});

// ============================================================================
// ROUTE 2: GET /api/books/:id - Display a single book by ID
// ============================================================================
app.get('/api/books/:id', (req, res) => {
    try {
        const bookId = req.params.id;
        const data = readBooksData();

        const book = data.books.find(b => b.id === bookId);

        if (!book) {
            return res.status(404).json({
                success: false,
                message: `Book not found with ID: ${bookId}`,
                suggestedIds: data.books.map(b => b.id)
            });
        }

        res.status(200).json({
            success: true,
            data: book
        });

    } catch (error) {
        console.error('Error fetching book:', error);
        res.status(500).json({
            success: false,
            message: 'Error fetching book from catalogue',
            error: error.message
        });
    }
});

// ============================================================================
// ROUTE 6: GET /api/books/:id/reviews - All reviews for a specific book
// ============================================================================
app.get('/api/books/:id/reviews', (req, res) => {
    try {
        const bookId = req.params.id;
        const { sort = 'date_desc', verified, rating } = req.query;

        const booksData = readBooksData();
        const reviewsData = readReviewsData();

        // Verify book exists
        const book = booksData.books.find(b => b.id === bookId);
        if (!book) {
            return res.status(404).json({
                success: false,
                message: `Book not found with ID: ${bookId}`,
                suggestedIds: booksData.books.map(b => b.id)
            });
        }

        // Get reviews for this book
        let bookReviews = reviewsData.reviews.filter(review => review.bookId === bookId);

        // Apply filters
        if (verified === 'true') {
            bookReviews = bookReviews.filter(review => review.verified === true);
        } else if (verified === 'false') {
            bookReviews = bookReviews.filter(review => review.verified === false);
        }

        if (rating && !isNaN(parseInt(rating))) {
            const ratingValue = parseInt(rating);
            bookReviews = bookReviews.filter(review => review.rating === ratingValue);
        }

        // Sort reviews
        let sortedReviews = [...bookReviews];
        switch (sort) {
            case 'rating_desc':
                sortedReviews.sort((a, b) => b.rating - a.rating);
                break;
            case 'rating_asc':
                sortedReviews.sort((a, b) => a.rating - b.rating);
                break;
            case 'date_desc':
                sortedReviews.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
                break;
            case 'date_asc':
                sortedReviews.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
                break;
            case 'author_asc':
                sortedReviews.sort((a, b) => a.author.localeCompare(b.author));
                break;
        }

        // Calculate review statistics
        const reviewStats = {
            total: bookReviews.length,
            averageRating: bookReviews.length > 0
                ? (bookReviews.reduce((sum, review) => sum + review.rating, 0) / bookReviews.length).toFixed(1)
                : 0,
            verifiedCount: bookReviews.filter(review => review.verified).length,
            ratingDistribution: {
                5: bookReviews.filter(review => review.rating === 5).length,
                4: bookReviews.filter(review => review.rating === 4).length,
                3: bookReviews.filter(review => review.rating === 3).length,
                2: bookReviews.filter(review => review.rating === 2).length,
                1: bookReviews.filter(review => review.rating === 1).length
            }
        };

        res.status(200).json({
            success: true,
            book: {
                id: book.id,
                title: book.title,
                author: book.author,
                overallRating: book.rating,
                totalReviews: book.reviewCount
            },
            statistics: reviewStats,
            filters: {
                sort,
                verified: verified || 'all',
                rating: rating || 'all'
            },
            count: sortedReviews.length,
            data: sortedReviews
        });

    } catch (error) {
        console.error('Error fetching book reviews:', error);
        res.status(500).json({
            success: false,
            message: 'Error fetching book reviews',
            error: error.message
        });
    }
});

// ============================================================================
// ENHANCED ROUTES (Bonus)
// ============================================================================

// GET /api/books/search - Search books by title, author, or description
app.get('/api/books/search', (req, res) => {
    try {
        const { q, genre, inStock, minRating } = req.query;

        if (!q) {
            return res.status(400).json({
                success: false,
                message: 'Search query parameter "q" is required'
            });
        }

        const data = readBooksData();

        let results = data.books.filter(book =>
            book.title.toLowerCase().includes(q.toLowerCase()) ||
            book.author.toLowerCase().includes(q.toLowerCase()) ||
            book.description.toLowerCase().includes(q.toLowerCase())
        );

        // Additional filters
        if (genre) {
            results = results.filter(book =>
                book.genre.some(g => g.toLowerCase().includes(genre.toLowerCase()))
            );
        }

        if (inStock === 'true') {
            results = results.filter(book => book.inStock);
        } else if (inStock === 'false') {
            results = results.filter(book => !book.inStock);
        }

        if (minRating && !isNaN(parseFloat(minRating))) {
            results = results.filter(book => book.rating >= parseFloat(minRating));
        }

        res.status(200).json({
            success: true,
            search: {
                query: q,
                filters: {
                    genre: genre || 'none',
                    inStock: inStock || 'none',
                    minRating: minRating || 'none'
                }
            },
            count: results.length,
            data: results
        });

    } catch (error) {
        console.error('Error searching books:', error);
        res.status(500).json({
            success: false,
            message: 'Error searching books',
            error: error.message
        });
    }
});

// ============================================================================
// START SERVER
// ============================================================================

app.listen(PORT, () => {
    console.log(`🚀 Amana Bookstore API running on port ${PORT}`);
    console.log(`📝 Logging to: ${path.join(__dirname, 'log.txt')}`);
    console.log(`🌐 Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`🔗 Health check: http://localhost:${PORT}/health`);
    console.log(`📚 API base: http://localhost:${PORT}/api/books`);
});

// Export app for testing
// module.exports = app;