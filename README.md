# Amana Bookstore Express API

A comprehensive Express.js REST API for the Amana Bookstore - a specialized academic bookstore focusing on science and educational texts.

## Features

- 📚 Book catalogue management
- ⭐ Review system with ratings
- 🔐 API key authentication
- 📊 Advanced filtering and search
- 📝 Request logging with Morgan
- 🚀 Ready for production deployment

## API Endpoints

### Public Routes
- `GET /` - API documentation
- `GET /health` - Health check
- `GET /api/books` - All books
- `GET /api/books/featured` - Featured books
- `GET /api/books/:id` - Single book
- `GET /api/books/:id/reviews` - Book reviews

### Authenticated Routes
- `POST /api/auth/login` - Get API key
- `POST /api/books` - Add new book (admin/publisher)
- `POST /api/reviews` - Add new review (admin/reviewer)

## Local Development

1. Install dependencies:
```bash
npm install