
package main

import (
    "fmt"
    "net"
    "os"
    "github.com/dedis/crypto/abstract"
    "vennard.ch/crypto"
)

type connectionhandler func(conn net.Conn)

func signOneKBSchnorr(conn net.Conn, suite abstract.Suite, kv crypto.SchnorrKeyset) {
    buffer := make([]byte, 1024)
    
    defer conn.Close()

    bytesRead, err := conn.Read(buffer)
    if err != nil {
        fmt.Printf("%d\n", err)
    }
  
    if bytesRead != 1024 {
        conn.Close()
    }

    signature, err := crypto.SchnorrSign(suite, kv, buffer)

    conn.Write(signature)
    if err != nil {
        fmt.Println(err.Error())
        os.Exit(1)
    }
    fmt.Println("Signed and responded to message.")
    conn.Close()
}

func serve(port int, handler connectionhandler) {
    
    if port < 1024 || port > 65535 {
        // todo: how does go handle errors.
    }

    portspec := fmt.Sprintf(":%d", port)

    sock, err := net.Listen("tcp", portspec)
    if err != nil {
        // error
        fmt.Printf("%d", err)
    }

    for {
        conn, err := sock.Accept()
        if err != nil {
            fmt.Printf("%d", err)     
        }
        go handler(conn) 
    }
}
