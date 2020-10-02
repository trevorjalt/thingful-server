const jwt = require('jsonwebtoken')
const AuthService = require('../auth/auth-service')

function requireAuth(req, res, next) {
    const authToken = req.get('Authorization') || ''

    let bearerToken
    if (!authToken.toLowerCase().startsWith('bearer ')) {
       return res.status(401).json({ error: 'Missing bearer token' })
    } else {
        bearerToken = authToken.slice('bearer '.length, authToken.length);
    }

    try {
      const payload = jwt.verify(bearerToken, process.env.JWT_SECRET);

      AuthService.getUserWithUserName(
        req.app.get('db'),
        payload.sub,
      )
        .then(user => {
          if (!user)
            return res.status(401).json({ error: 'Unauthorized request' })
            
          req.user = user
          next()
        })
        .catch(err => {
          console.error(err)
          next(err)
        })
    } catch(error) {
      res.status(401).json({ error: 'Unauthorized request' })
    }
}
  
  module.exports = {
    requireAuth,
  }