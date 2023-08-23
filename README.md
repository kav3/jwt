# JWT
ES6 Compatible JWT Module

## Install

    $ npm install @kav3/jwt

## Usage

    import { encode, decode, random } from  '@kav3/jwt'
    random().then(SECRET_KEY => {
	const token = encode({a:1, b:2}, SECRET_KEY)
	console.log("SECRET_KEY: ", SECRET_KEY)
	console.log("token: ", token)
	console.log("payload: ", decode(token, SECRET_KEY))
	})
   

    
