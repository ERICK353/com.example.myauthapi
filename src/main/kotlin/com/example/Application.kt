package com.example

import com.example.data.user.MongoUserDataSource
import com.example.data.user.User
import com.example.plugins.*
import com.example.security.hashing.SHA256HashingService
import com.example.security.token.JwtTokenService
import com.example.security.token.TokenConfig
import io.ktor.server.application.*
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
import org.litote.kmongo.coroutine.coroutine
import org.litote.kmongo.reactivestreams.KMongo

fun main(args: Array<String>) {
    io.ktor.server.netty.EngineMain.main(args)
}

fun Application.module() {
    val MongoPass=System.getenv("MongoPass")
    val dbName="errands"
    val db=KMongo.createClient(
        connectionString = "mongodb+srv://erick:$MongoPass@cluster0.29krbce.mongodb.net/$dbName?retryWrites=true&w=majority&appName=Cluster0"
    ).coroutine
        .getDatabase(dbName)
    val userDataSource=MongoUserDataSource(db)
    val tokenService=JwtTokenService()
    val tokenConfig=TokenConfig(
        issuer = environment.config.property("jwt.issuer").getString(),
        audience = environment.config.property("jwt.audience").getString(),
        expiresIn=356L * 1000L * 60L * 60L *24L,
        secret=System.getenv("JWT_SECRET")
    )
    val hashingService=SHA256HashingService()
    configureMonitoring()
    configureSecurity(tokenConfig)
    configureSerialization()
    configureRouting(userDataSource, hashingService, tokenService, tokenConfig)
}
