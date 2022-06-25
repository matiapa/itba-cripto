# Compilación

En la carpeta raiz ejecutar ``mvn pckg``, esto generará un JAR en ``target``.

Alternativamente, descargar el JAR desde los Releases del repositorio.

# Ejecución

Ejecutar el JAR con la opción ``-h`` para obtener el siguiente menú de ayuda.

    usage: Steganography
    -a <arg>      Encryption cypher method <aes128 | aes192 | aes256 | des>
    -embed        Embed a payload into a host
    -extract      Extract payload from a host
    -h,--help     Prints help message
    -in <arg>     Payload file (only when embedding)
    -m <arg>      Encryption chaining method <ecb | cfb | ofb | cbc>
    -out <arg>    Output file (tampered host when embedding, payload when
    extracting)
    -p <arg>      Host file (original when embedding, tampered when
    extracting
    -pass <arg>   Encryption password
    -steg <arg>   Steganography method: <LSB1 | LSB4 | LSBI>
