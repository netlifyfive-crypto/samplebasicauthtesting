const VALID_CREDENTIALS = process.env.BASIC_AUTH_CREDENTIALS || 'admin:password123';

exports.handler = async (event, context) => {
  // Allow both GET and POST
  const allowedMethods = ['GET', 'POST'];
  if (!allowedMethods.includes(event.httpMethod)) {
    return {
      statusCode: 405,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ error: 'Method not allowed' })
    };
  }

  const authHeader = event.headers.authorization || 
                    event.headers.Authorization ||
                    event.headers['Authorization'];

  if (!authHeader || !authHeader.startsWith('Basic ')) {
    return {
      statusCode: 401,
      headers: {
        'WWW-Authenticate': 'Basic realm="Secure Area"',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ error: 'Authorization required' })
    };
  }

  try {
    const credentials = Buffer.from(authHeader.split(' ')[1], 'base64').toString();
    const [username, password] = credentials.split(':');

    const validCreds = VALID_CREDENTIALS.split('|');
    const isValid = validCreds.some(cred => {
      const [validUser, validPass] = cred.split(':');
      return validUser === username && validPass === password;
    });

    if (!isValid) {
      return {
        statusCode: 401,
        headers: {
          'WWW-Authenticate': 'Basic realm="Secure Area"',
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ error: 'Invalid credentials' })
      };
    }

    return {
      statusCode: 200,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        message: 'Authenticated successfully',
        username: username,
        token: 'basic-auth-token-' + Date.now()
      })
    };
  } catch (error) {
    return {
      statusCode: 400,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ error: 'Invalid authorization header' })
    };
  }
};
