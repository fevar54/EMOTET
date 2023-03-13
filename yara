rule amenaza_emotet {
meta:
        description = "Detects Emotet malware"
        author = "Fevar54"
    condition:
        any of them
            for any hash in ( "057e0bbcf5b24140d7a22f9c55ad82e7", "2397a3ecbc67479f3daffdb53b3fa6e9", "6851f2f307480ff2e2c44a34c3576aa4" ) : 
            hash == md5sum or hash == sha1sum or hash == sha256sum
}
