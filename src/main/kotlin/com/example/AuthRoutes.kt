package com.example

import com.example.authenticate
import com.example.data.request.AuthRequest
import com.example.data.responses.AuthResponse
import com.example.data.user.MongoUserDataSource
import com.example.data.user.User
import com.example.data.user.UserDataSource
import com.example.security.hashing.HashingService
import com.example.security.hashing.SaltedHash
import com.example.security.token.TokenClaim
import com.example.security.token.TokenConfig
import com.example.security.token.TokenService
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.auth.jwt.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import org.apache.commons.codec.digest.DigestUtils

fun Route.signUp(
    hashingService: HashingService,
    userDataSource: UserDataSource
){
post("signup"){
    val request= call.receiveOrNull<AuthRequest>()?:kotlin.run {
        call.respond(HttpStatusCode.BadRequest)
        return@post
    }
    val areFieldsBlank=request.username.isBlank() || request.password.isBlank()
    val userExist =userDataSource.getUserByUsername(request.username)
    val isPwTooShort=request.password.length<6
    if(areFieldsBlank||isPwTooShort){
        call.respond(HttpStatusCode.Conflict,)
        return@post

    }
    if(userExist !=null){
        call.respond(HttpStatusCode.Conflict,"User already Exists")
        return@post

    }

    val saltedHash=hashingService.generateSaltedHash(request.password)
    val user= User(
        username=request.username,
        password=saltedHash.hash,
        salt=saltedHash.salt
    )
    val wasAcknowledged=userDataSource.insertUser(user)
    if(!wasAcknowledged){
        call.respond(HttpStatusCode.Conflict)
        return@post
    }
call.respond(HttpStatusCode.OK,"Account Created Successfully")
}

}
fun Route.signIn(
hashingService: HashingService,
userDataSource: UserDataSource,
tokenService: TokenService,
tokenConfig: TokenConfig
){
    post("signin") {
        val request = call.receiveOrNull<AuthRequest>() ?: kotlin.run {
            call.respond(HttpStatusCode.BadRequest)
            return@post
        }
        val user =userDataSource.getUserByUsername(request.username)
        if(user==null){
            call.respond(HttpStatusCode.Conflict,"Incorrect Username or Password")
            return@post
        }

        val isValidPassword=hashingService.verify(
            value = request.password,
            saltedHash = SaltedHash(
                hash=user.password,
                salt=user.salt
            )

        )
        if(!isValidPassword){
            println("Entered hash: ${DigestUtils.sha256Hex("${user.salt}${request.password}")}, Hashed PW: ${user.password}")
            call.respond(HttpStatusCode.Conflict,"Incorrect   Password=+$isValidPassword")
            return@post
        }
        val token=tokenService.generate(
         config=tokenConfig, TokenClaim(
        name="userId",
        value=user.id.toString()
             )
            )
        call.respond(
            status = HttpStatusCode.OK,
            message = AuthResponse(
                token=token
            )
        )
    }
}
fun Route.authenticate(){
    authenticate {
        get("authenticate"){
            call.respond(HttpStatusCode.OK)
        }


    }
}

fun Route.getSecretInfo(){
    authenticate{
        get("secret"){
            val principal=call.principal<JWTPrincipal>()
            val userId=principal?.getClaim("userId",String::class)
            call.respond(HttpStatusCode.OK,"Your userId$userId")
        }
    }
}
