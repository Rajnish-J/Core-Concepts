# Comprehensive Backend Engineering Guide

## Introduction

Backend engineering encompasses much more than building a set of CRUD APIs. It's about building **reliable**, **scalable**, **fault-tolerant**, and **maintainable** codebases and efficient systems.

### The Challenge

When starting backend development today, there are thousands of resources available, but the key challenges are:

- **How to decide what to learn**
- **How to prioritize learning**
- **How to see the big picture** and understand how different concepts come together

### Common Problems

1. **Limited scope training** from colleges, boot camps, or simple courses
2. **Language/Framework-specific approach** (Express, Spring Boot, Ruby on Rails)
   - Creates blind spots when viewing problems through a particular language lens
   - Knowledge transfer difficulties when switching languages (e.g., Ruby on Rails to Golang)
3. **Time-consuming learning process** involving trial and error

### This Guide's Approach

This comprehensive guide is based on:

- **Foundational concepts** of backend systems
- Knowledge from various books on backend development
- Analysis of hundreds of open-source codebases
- Industry best practices and patterns

## 1. High-Level Backend System Architecture

### Request Flow Overview

Understanding how a request flows from browser through different network hops:

- **Browser** → **Network** → **Firewalls** → **Internet** → **Remote AWS Server**
- How the backend server processes and responds to requests
- **Client-Server communication patterns**
- Response structure and format

This foundation provides a vivid understanding of:

- How systems communicate
- Client-server interaction patterns
- Server response mechanisms

## 2. HTTP Protocol Deep Dive

### Core HTTP Concepts

#### HTTP Protocol Role

- How communication is established through HTTP
- Structure of HTTP raw messages
- Request-response cycle mechanics

#### HTTP Headers

Understanding different types of headers:

**Request Headers**

- Client information and preferences
- Authentication tokens
- Content negotiation

**Response Headers**

- Server information and metadata
- Caching directives
- Security policies

**General Headers**

- Apply to both requests and responses
- Connection management
- Transfer encoding

**Security Headers**

- Content Security Policy (CSP)
- X-Content-Type-Options
- Strict-Transport-Security

#### HTTP Methods and Semantics

**GET Method**

- Retrieving resources
- Idempotent and safe operations
- Caching considerations

**POST Method**

- Creating resources
- Non-idempotent operations
- Data submission

**PUT Method**

- Complete resource updates
- Idempotent operations
- Replace entire resource

**DELETE Method**

- Resource removal
- Idempotent operations
- Cleanup procedures

**PATCH Method**

- Partial resource updates
- Non-idempotent operations
- Targeted modifications

### CORS (Cross-Origin Resource Sharing)

#### CORS Flow

- **Simple requests** vs **Preflight requests**
- Browser to server preflight flow
- Response handling for CORS

#### CORS Headers

- `Access-Control-Allow-Origin`
- `Access-Control-Allow-Methods`
- `Access-Control-Allow-Headers`
- `Access-Control-Max-Age`

### HTTP Responses

#### Response Structure

- Status line
- Response headers
- Response body

#### HTTP Status Codes

**1xx Informational**

- 100 Continue
- 101 Switching Protocols

**2xx Success**

- 200 OK
- 201 Created
- 204 No Content

**3xx Redirection**

- 301 Moved Permanently
- 302 Found
- 304 Not Modified

**4xx Client Error**

- 400 Bad Request
- 401 Unauthorized
- 403 Forbidden
- 404 Not Found

**5xx Server Error**

- 500 Internal Server Error
- 502 Bad Gateway
- 503 Service Unavailable

### HTTP Caching

#### Caching Techniques

**ETags (Entity Tags)**

- Resource versioning
- Conditional requests
- Cache validation

**Cache-Control Headers**

- `max-age` directive
- `no-cache` and `no-store`
- `must-revalidate`

**Expiration Model**

- `Expires` header
- Time-based caching
- Cache freshness

### HTTP Versions

#### HTTP/1.1

- Persistent connections
- Pipelining limitations
- Head-of-line blocking

#### HTTP/2.0

- Binary protocol
- Multiplexing
- Server push
- Header compression

#### HTTP/3.0

- Built on QUIC protocol
- Reduced latency
- Improved performance

### Content Negotiation

- Client-server header-based negotiation
- `Accept` headers for media types
- `Accept-Language` for localization
- `Accept-Encoding` for compression

### Persistent Connections

- Connection reuse
- Keep-alive mechanisms
- Performance benefits

### HTTP Compression

#### Compression Techniques

**GZIP**

- Most commonly used
- Good compression ratio
- Wide browser support

**Deflate**

- Alternative compression
- Less common usage

**Brotli (BR)**

- Modern compression algorithm
- Better compression than GZIP
- Growing browser support

### Security: SSL/TLS and HTTPS

- Transport Layer Security
- Certificate management
- Encryption protocols
- HTTPS implementation

## 3. Routing

### Routing Fundamentals

- **URL mapping** to server-side logic
- Connection between **routing** and **HTTP methods**
- Request routing pipeline

### Route Components

#### Path Parameters

```
/users/:id
/api/v1/products/:productId
```

#### Query Parameters

```
/search?q=backend&page=1&limit=10
```

### Route Types

#### Static Routes

- Fixed URL patterns
- No dynamic components
- Direct mapping

#### Dynamic Routes

- Variable path segments
- Parameter extraction
- Flexible matching

#### Nested Routes

- Hierarchical URL structure
- Parent-child relationships
- Modular organization

#### Hierarchical Routes

- Tree-like route structure
- Inheritance patterns
- Shared middleware

#### Catch-all/Wildcard Routes

- Fallback routing
- 404 handling
- Flexible matching patterns

#### Regular Expression Routes

- Pattern-based matching
- Complex URL validation
- Advanced routing logic

### API Versioning

#### Versioning Techniques

**URI Versioning**

```
/api/v1/users
/api/v2/users
```

**Header Versioning**

```
Accept: application/vnd.api+json;version=1
```

**Query Parameter Versioning**

```
/api/users?version=1
```

**Media Type Versioning**

```
Accept: application/vnd.company.user-v1+json
```

#### Deprecation Best Practices

- Gradual phase-out strategies
- Clear communication timelines
- Backward compatibility maintenance

### Route Management

#### Route Grouping Benefits

- **Versioning** organization
- **Permission** management
- **Shared middleware** application
- Code organization

#### Route Security

- Authentication middleware
- Authorization checks
- Rate limiting
- Input validation

#### Route Performance Optimization

- Route matching efficiency
- Caching strategies
- Middleware ordering
- Performance profiling

## 4. Serialization and Deserialization

### Core Concepts

#### Serialization

Converting native data structures to a format suitable for network transmission or storage.

#### Deserialization

Converting received data from network format back to native programming language format.

### Purpose and Benefits

- **Interoperability** between different systems
- **Standardized** data exchange
- **Cross-platform** communication
- **Data persistence** capabilities

### Serialization Formats

#### Text-Based Formats

**JSON (JavaScript Object Notation)**

- Human-readable
- Wide language support
- Web-friendly
- Larger payload size

**XML (eXtensible Markup Language)**

- Self-describing
- Schema validation
- Verbose structure
- Legacy system support

#### Binary Formats

**Protocol Buffers (Protobuf)**

- Compact binary format
- Fast serialization/deserialization
- Schema evolution
- Cross-language support

**MessagePack**

- Efficient binary format
- JSON-like data model
- Smaller size than JSON

### Performance Considerations

#### Text vs Binary Format Trade-offs

**Text-Based (JSON) Advantages:**

- Human-readable and debuggable
- Easy to inspect payloads
- Wide tooling support
- Simple implementation

**Binary Format (Protobuf) Advantages:**

- Faster serialization/deserialization
- Smaller payload size
- Type safety
- Schema enforcement

**When to Use Each:**

- **Text formats**: Development, debugging, simple APIs
- **Binary formats**: High-performance systems, large data volumes

### JSON Deep Dive

#### JSON Structure

```json
{
  "string": "value",
  "number": 123,
  "boolean": true,
  "array": [1, 2, 3],
  "object": {
    "nested": "property"
  },
  "null": null
}
```

#### JSON Data Types

- **Strings**: Text data in quotes
- **Numbers**: Integer or floating-point
- **Booleans**: true/false values
- **Arrays**: Ordered lists
- **Objects**: Key-value pairs
- **Null**: Null values

#### Nested Objects and Collections

```json
{
  "users": [
    {
      "id": 1,
      "profile": {
        "name": "John",
        "contacts": ["email", "phone"]
      }
    }
  ]
}
```

#### Language-Specific Deserialization

**Python Dictionary**

```python
import json
data = json.loads(json_string)
user_name = data['users'][0]['profile']['name']
```

**Go Structs**

```go
type User struct {
    ID   int    `json:"id"`
    Name string `json:"name"`
}
```

**JavaScript Objects**

```javascript
const data = JSON.parse(jsonString);
const userName = data.users[0].profile.name;
```

### Common JSON Handling Errors

#### Missing or Extra Fields

- Handling optional properties
- Graceful degradation
- Schema validation

#### Null Value Handling

- Null vs undefined
- Default value strategies
- Type safety

#### Date Serialization Issues

- ISO 8601 format standardization
- Timezone handling
- Custom date parsers

#### Custom Serialization

- Custom field naming
- Data transformation
- Computed properties

### Error Handling in Serialization

#### Invalid Data Handling

- Malformed JSON
- Type conversion errors
- Schema validation failures

#### Unknown Fields

- Strict vs lenient parsing
- Forward compatibility
- Schema evolution

### Security Concerns

#### Injection Attacks

- JSON injection prevention
- Input sanitization
- Payload size limits

#### Validation Requirements

- **Pre-deserialization validation**
- Schema-based validation
- Custom validation rules

#### JSON Schema Validation

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "properties": {
    "name": { "type": "string" },
    "age": { "type": "integer", "minimum": 0 }
  },
  "required": ["name"]
}
```

### Performance Optimization

#### Data Compression

- GZIP compression
- Reduced payload sizes
- Network optimization

#### Field Elimination

- Remove unnecessary fields
- Selective serialization
- Payload optimization

#### Serialization Performance

- Text vs binary benchmarks
- Memory usage optimization
- CPU utilization considerations

## 5. Authentication and Authorization

### Authentication Types

#### Stateful Authentication

- Server-side session storage
- Session cookies
- Memory/database persistence

#### Stateless Authentication

- JWT tokens
- Self-contained credentials
- No server-side storage

#### Basic Authentication

- Username:password encoding
- Base64 encoding
- HTTP headers

#### Token-Based Authentication

- Bearer tokens
- API keys
- OAuth tokens

### Authentication Mechanisms

#### Sessions

- Server-side session management
- Session ID generation
- Session storage strategies

#### JWT (JSON Web Tokens)

```
Header.Payload.Signature
```

- Stateless authentication
- Self-contained tokens
- Digital signatures

#### Cookies

- HTTP-only cookies
- Secure cookie flags
- SameSite attributes

#### OAuth Protocol

- Third-party authentication
- Authorization code flow
- Implicit flow
- Client credentials flow

#### OpenID Connect

- Identity layer on OAuth 2.0
- User information endpoint
- ID tokens

#### API Keys

- Application authentication
- Rate limiting
- Access control

#### Multi-Factor Authentication (MFA)

- Something you know (password)
- Something you have (device)
- Something you are (biometric)

### Cryptographic Techniques

#### Salting

- Password randomization
- Rainbow table prevention
- Unique salt per password

#### Hashing

- One-way functions
- Password storage
- Data integrity

**Common Hash Algorithms:**

- bcrypt
- scrypt
- Argon2
- PBKDF2

### Authorization Models

#### ABAC (Attribute-Based Access Control)

- Dynamic authorization
- Context-aware decisions
- Fine-grained control

#### RBAC (Role-Based Access Control)

- Role assignment
- Permission inheritance
- Hierarchical roles

#### ReBAC (Relationship-Based Access Control)

- Graph-based permissions
- Social relationships
- Complex authorization

### Security Best Practices

#### Cookie Security

- HttpOnly flags
- Secure flags
- SameSite attributes
- Domain restrictions

#### Attack Prevention

**CSRF (Cross-Site Request Forgery)**

- CSRF tokens
- SameSite cookies
- Origin validation

**XSS (Cross-Site Scripting)**

- Input sanitization
- Output encoding
- Content Security Policy

**MITM (Man-in-the-Middle)**

- HTTPS enforcement
- Certificate pinning
- Secure communication

### Audit and Logging

#### Authentication Events

- Login attempts
- Failed authentications
- Password changes
- Account lockouts

#### Authorization Events

- Permission grants/denials
- Privilege escalation
- Resource access
- Administrative actions

#### Monitoring and Alerting

- Failed login tracking
- Brute force detection
- Anomaly detection
- Real-time alerts

### Error Handling Security

#### Error Message Obfuscation

- Generic error messages
- Information leakage prevention
- Consistent response times

**Example:**

```
Bad: "Invalid password for user john@example.com"
Good: "Invalid credentials"
```

#### Timing Attack Prevention

- Consistent response times
- Cryptographic time equality
- Hash comparison techniques

#### Rate Limiting

- Login attempt limits
- Account lockout policies
- Progressive delays

#### Edge Cases

- Consistency in failure modes
- Error response standardization
- Security-first design

## 6. Validation and Transformation

### Types of Validation

#### Syntactic Validation

**Format Validation:**

- Email format validation
- Phone number patterns
- Date format verification
- URL structure validation

**Regular Expression Examples:**

```regex
Email: ^[^\s@]+@[^\s@]+\.[^\s@]+$
Phone: ^\+?[1-9]\d{1,14}$
Date: ^\d{4}-\d{2}-\d{2}$
```

#### Semantic Validation

**Business Logic Validation:**

- Date of birth cannot be in the future
- Age must be between 1 and 120
- Start date must be before end date
- Salary must be positive

#### Type Validation

**Data Type Checking:**

- String validation
- Integer/number validation
- Array validation
- Object structure validation
- Boolean validation

### Validation Best Practices

#### Client-Side vs Server-Side Validation

**Client-Side Validation:**

- **Purpose**: User experience improvement
- **Benefits**: Instant feedback, reduced server load
- **Limitations**: Easily bypassed, security risk if alone

**Server-Side Validation:**

- **Purpose**: Security and data integrity
- **Requirements**: Always implement regardless of client validation
- **Role**: Gateway to business logic

#### Fail-Fast Principle

- **Early termination** on validation failure
- **Reduced processing** overhead
- **Quick error response** to clients
- **Resource conservation**

#### Consistency Requirements

- **Frontend-backend alignment**
- **Uniform validation rules**
- **Synchronized error messages**
- **Coordinated updates**

### Data Transformation

#### Type Casting

**Common Transformations:**

```javascript
// String to Number
const id = parseInt(req.params.id);
const price = parseFloat(req.body.price);

// Number to String
const idString = id.toString();
```

**Query Parameter Handling:**

- All query parameters are strings by default
- Convert to expected types before processing
- Handle conversion errors gracefully

#### Date Format Transformation

**Frontend to Backend:**

```javascript
// Frontend might send: "2024-12-25"
// Backend expects: Unix timestamp
const timestamp = new Date(dateString).getTime();
```

**Timezone Handling:**

- Convert to UTC for storage
- Handle timezone offsets
- Maintain timezone information when needed

#### Normalization

**Email Normalization:**

```javascript
const normalizedEmail = email.toLowerCase().trim();
```

**Phone Number Normalization:**

```javascript
// Add country code if missing
const normalizedPhone = phone.startsWith("+") ? phone : `+1${phone}`;
```

**String Normalization:**

```javascript
const normalized = input.trim().toLowerCase();
```

#### Sanitization for Security

**SQL Injection Prevention:**

```javascript
// Remove or escape dangerous characters
const sanitized = input.replace(/['";\\]/g, "");
```

**XSS Prevention:**

```javascript
// HTML entity encoding
const sanitized = input
  .replace(/&/g, "&amp;")
  .replace(/</g, "&lt;")
  .replace(/>/g, "&gt;");
```

### Complex Validation Logic

#### Relationship Validation

```javascript
// Password confirmation
if (password !== confirmPassword) {
  throw new ValidationError("Passwords do not match");
}
```

#### Conditional Validation

```javascript
// Partner name required if married
if (married === true && !partnerName) {
  throw new ValidationError("Partner name is required for married individuals");
}
```

#### Chain Validation

```javascript
const processedValue = input
  .toLowerCase() // Step 1: Normalize case
  .replace(/[^\w]/g, "") // Step 2: Remove special characters
  .substring(0, 50); // Step 3: Limit length
```

### Error Handling in Validation

#### Meaningful Error Messages

```javascript
// Good error messages
{
  "errors": [
    {
      "field": "email",
      "message": "Email format is invalid",
      "code": "INVALID_EMAIL_FORMAT"
    },
    {
      "field": "age",
      "message": "Age must be between 18 and 100",
      "code": "AGE_OUT_OF_RANGE"
    }
  ]
}
```

#### Error Aggregation

- **Collect all validation errors**
- **Single response** with all issues
- **Client-side display** optimization
- **Reduced round trips**

#### Error Message Obfuscation

```javascript
// Security-focused error messages
// Instead of: "Password must contain uppercase letter"
// Use: "Password does not meet requirements"
```

### Failed Transformation Handling

#### JSON Parsing Errors

```javascript
try {
  const data = JSON.parse(request.body);
} catch (error) {
  throw new ValidationError("Invalid JSON format");
}
```

#### Date Conversion Failures

```javascript
const date = new Date(dateString);
if (isNaN(date.getTime())) {
  throw new ValidationError("Invalid date format");
}
```

#### Graceful Error Response

```javascript
{
  "error": "VALIDATION_FAILED",
  "message": "Request data could not be processed",
  "details": {
    "field": "birthDate",
    "received": "invalid-date-string",
    "expected": "YYYY-MM-DD format"
  }
}
```

### Performance Optimization

#### Early Return Strategy

```javascript
// Return immediately on first validation failure
if (!email) {
  return { error: "Email is required" };
}
if (!isValidEmail(email)) {
  return { error: "Email format invalid" };
}
```

#### Avoiding Redundant Validations

- **Cache validation results** when possible
- **Skip expensive validations** after simpler ones fail
- **Optimize validation order** (cheap validations first)

#### Validation Pipeline Efficiency

- **Parallel validation** where possible
- **Asynchronous validation** for external checks
- **Batch validation** for multiple items

## 7. Middleware

### Middleware Fundamentals

#### What is Middleware?

Middleware are functions that execute during the request-response cycle, sitting between the raw request and the final route handler.

#### When to Use Middleware

- **Cross-cutting concerns** (logging, authentication)
- **Reusable functionality** across routes
- **Request/response modification**
- **Error handling**
- **Security implementations**

### Middleware in Request Cycle

#### Pre-Request Middleware

- Execute before reaching route handlers
- Request modification and validation
- Authentication and authorization
- Logging and monitoring

#### Post-Response Middleware

- Execute after route handler completion
- Response modification
- Cleanup operations
- Final logging

### Middleware Flow and Chaining

#### Sequential Execution

```javascript
app.use(middleware1); // Executes first
app.use(middleware2); // Executes second
app.use(middleware3); // Executes third
```

#### Control Flow

```javascript
function middleware(req, res, next) {
  // Pre-processing
  console.log("Before next()");

  next(); // Pass control to next middleware

  // Post-processing
  console.log("After next()");
}
```

#### Middleware Ordering Importance

**Correct Order:**

1. **Request Logging** - Track all incoming requests
2. **Authentication** - Verify user identity
3. **Authorization** - Check permissions
4. **Validation** - Validate request data
5. **Route Handler** - Process business logic
6. **Error Handling** - Handle any errors

### Next Function and Flow Control

#### Continuing the Chain

```javascript
function authMiddleware(req, res, next) {
  if (isAuthenticated(req)) {
    next(); // Continue to next middleware
  } else {
    res.status(401).json({ error: "Unauthorized" });
    // Don't call next() - stop the chain
  }
}
```

#### Early Exit

```javascript
function rateLimitMiddleware(req, res, next) {
  if (exceedsRateLimit(req)) {
    return res.status(429).json({ error: "Rate limit exceeded" });
    // Chain stops here, no next() called
  }
  next();
}
```

#### Error Propagation

```javascript
function errorProneMiddleware(req, res, next) {
  try {
    // Some operation that might fail
    riskyOperation();
    next();
  } catch (error) {
    next(error); // Pass error to error handling middleware
  }
}
```

### Common Middleware Types

#### Security Middleware

**Security Headers:**

```javascript
function securityHeaders(req, res, next) {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-XSS-Protection", "1; mode=block");
  res.setHeader("Strict-Transport-Security", "max-age=31536000");
  next();
}
```

**CORS Middleware:**

```javascript
function corsMiddleware(req, res, next) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  next();
}
```

**CSRF Protection:**

```javascript
function csrfProtection(req, res, next) {
  const token = req.headers["x-csrf-token"];
  if (!isValidCSRFToken(token)) {
    return res.status(403).json({ error: "CSRF token invalid" });
  }
  next();
}
```

#### Rate Limiting Middleware

```javascript
function rateLimiter(req, res, next) {
  const clientId = getClientId(req);
  const requests = getRequestCount(clientId);

  if (requests > RATE_LIMIT) {
    return res.status(429).json({
      error: "Rate limit exceeded",
      retryAfter: getRetryAfter(clientId),
    });
  }

  incrementRequestCount(clientId);
  next();
}
```

#### Authentication Middleware

```javascript
function authenticate(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Authentication required" });
  }

  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    req.user = decoded; // Add user to request context
    next();
  } catch (error) {
    return res.status(401).json({ error: "Invalid token" });
  }
}
```

#### Logging and Monitoring

**Request Logging:**

```javascript
function requestLogger(req, res, next) {
  const start = Date.now();

  console.log(`${req.method} ${req.url} - ${req.ip}`);

  res.on("finish", () => {
    const duration = Date.now() - start;
    console.log(`${req.method} ${req.url} - ${res.statusCode} - ${duration}ms`);
  });

  next();
}
```

**Structured Logging:**

```javascript
function structuredLogger(req, res, next) {
  const requestId = generateRequestId();
  req.requestId = requestId;

  logger.info({
    requestId,
    method: req.method,
    url: req.url,
    userAgent: req.headers["user-agent"],
    timestamp: new Date().toISOString(),
  });

  next();
}
```

#### Error Handling Middleware

```javascript
function errorHandler(error, req, res, next) {
  logger.error({
    error: error.message,
    stack: error.stack,
    requestId: req.requestId,
    url: req.url,
  });

  // Don't expose internal errors to client
  const statusCode = error.statusCode || 500;
  const message = statusCode === 500 ? "Internal Server Error" : error.message;

  res.status(statusCode).json({
    error: message,
    requestId: req.requestId,
  });
}
```

#### Compression Middleware

```javascript
function compressionMiddleware(req, res, next) {
  const acceptEncoding = req.headers["accept-encoding"] || "";

  if (acceptEncoding.includes("gzip")) {
    res.setHeader("Content-Encoding", "gzip");
    // Compress response body
  }

  next();
}
```

#### Data Parsing Middleware

**JSON Parser:**

```javascript
function jsonParser(req, res, next) {
  if (req.headers["content-type"] === "application/json") {
    let body = "";

    req.on("data", (chunk) => {
      body += chunk.toString();
    });

    req.on("end", () => {
      try {
        req.body = JSON.parse(body);
        next();
      } catch (error) {
        return res.status(400).json({ error: "Invalid JSON" });
      }
    });
  } else {
    next();
  }
}
```

**Multipart Form Handler:**

```javascript
function multipartHandler(req, res, next) {
  if (req.headers["content-type"]?.includes("multipart/form-data")) {
    // Handle file uploads and form data
    parseMultipartData(req, (error, fields, files) => {
      if (error) {
        return res.status(400).json({ error: "Invalid form data" });
      }
      req.body = fields;
      req.files = files;
      next();
    });
  } else {
    next();
  }
}
```

### Performance and Scalability

#### Lightweight Middleware Best Practices

- **Minimal processing** in middleware
- **Avoid blocking operations**
- **Use async operations** when needed
- **Early exits** to avoid unnecessary processing

#### Middleware Ordering for Performance

```javascript
app.use(cors);
app.use(rateLimit);
app.use(authenticate);
app.use(validateRequest);
app.use(routes);
app.use(errorHandler);
```

#### Conditional Middleware Application

```javascript
app.use("/api/protected/*", authenticate);
app.use("/api/admin/*", authenticate, authorize("admin"));
```

#### Caching in Middleware

```javascript
function cacheMiddleware(req, res, next) {
  const cacheKey = generateCacheKey(req);
  const cached = cache.get(cacheKey);

  if (cached) {
    return res.json(cached); // Skip route handler
  }

  // Override res.json to cache response
  const originalJson = res.json;
  res.json = function (data) {
    cache.set(cacheKey, data, CACHE_TTL);
    return originalJson.call(this, data);
  };

  next();
}
```

## 8. Request Context

### Request Context Fundamentals

#### What is Request Context?

Request context is **metadata and state** that persists throughout the lifecycle of a single HTTP request, providing a way to share data across different layers of the application without tight coupling.

#### Key Characteristics

- **Request-scoped**: Only valid for the duration of one request
- **Temporary state**: Cleaned up after request completion
- **Cross-layer sharing**: Available in middlewares, controllers, services
- **Decoupled**: Reduces parameter passing between functions

### Request Context Lifecycle

#### Lifecycle Stages

1. **Context Creation** - Initialized when request arrives
2. **Data Injection** - Middlewares add information
3. **Context Usage** - Controllers and services access data
4. **Context Cleanup** - Memory freed after response

#### Data Flow Example

```
Request → Middleware → Context → Controller → Service → Response
         ↓
    (User info, Request ID, Permissions)
```

### Context Components

#### Request Metadata

**HTTP Information:**

```javascript
const context = {
  method: "POST",
  url: "/api/users",
  headers: {
    "content-type": "application/json",
    "user-agent": "Mozilla/5.0...",
  },
  query: { page: 1, limit: 10 },
  body: { name: "John", email: "john@example.com" },
};
```

#### Session and User Information

```javascript
// Added by authentication middleware
const context = {
  user: {
    id: 12345,
    email: "user@example.com",
    roles: ["user", "premium"],
    permissions: ["read:profile", "write:profile"],
  },
  session: {
    sessionId: "sess_abc123",
    createdAt: "2024-01-15T10:30:00Z",
    expiresAt: "2024-01-15T12:30:00Z",
  },
};
```

#### Tracking and Logging Information

```javascript
const context = {
  requestId: "req_uuid_12345",
  traceId: "trace_67890",
  correlationId: "corr_abcdef",
  startTime: Date.now(),
  clientIp: "192.168.1.100",
};
```

#### Request-Specific Data

```javascript
const context = {
  // Caching data
  cacheKeys: ['user:12345', 'permissions:12345'],

  // Permission check results
  permissions: {
    'read:users': true,
    'write:users': false
  },

  // Custom middleware data
  rateLimit: {
    remaining: 98,
```
