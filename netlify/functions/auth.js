const VALID_CREDENTIALS = process.env.BASIC_AUTH_CREDENTIALS || 'admin:password123';

exports.handler = async (event, context) => {
  if (event.httpMethod !== 'POST') {
    return {
      statusCode: 405,
      body: JSON.stringify({ error: 'Method not allowed' })
    };
  }

  const authHeader = event.headers.authorization || event.headers.Authorization;

  if (!authHeader || !authHeader.startsWith('Basic ')) {
    return {
      statusCode: 401,
      headers: {
        'WWW-Authenticate': 'Basic realm="Secure Area"'
      },
      body: JSON.stringify({ error: 'Authorization required' })
    };
  }

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
        'WWW-Authenticate': 'Basic realm="Secure Area"'
      },
      body: JSON.stringify({ error: 'Invalid credentials' })
    };
  }

  return {
    statusCode: 200,
    body: JSON.stringify({
      message: 'Authenticated successfully',
      token: 'basic-auth-token-' + Date.now()
    })
  };
};
