# ciri-stormrider

Golang implementation for JWT web token used primarily for projects under EarmuffJam Repository.

## Anatomy of a single Jwt Token

Jwt tokens are made of of three parts which are

    header :: specifies the algorithm that is used to generate the signature. this is a common practice however
    it might be possible that some prefer other methods of corrospondence.

    payload :: specifies application specific information, along with the validity and expiration of the token.

    signature :: specifies the signing block of the jwt token. it is generated by combining and hashing the first two parts along with a secret key together.

`Note` that the header and payload are not **encrypted** - they are rather just Base64 encoded. This means that anyone can decode them using a base64 decoder.

## How does the Jwt token work

The Jwt token is made secure by the third portion of the token. This is also known as the `signature`. How this signature is generated is where the cue lies on how the security takes into effect. the algorithm is **`one way`** which means that we cannot reverse the algorithm. This way we will never know what components went into making the signature.

By doing such we are able to keep our key secret. For the use case of our small project, we are using `uuid` generator from the package -`"github.com/google/uuid"`.

`Go Dependencies Used`

```
github.com/dgrijalva/jwt-go v3.2.0+incompatible
github.com/google/uuid v1.3.0
github.com/gorilla/mux v1.8.0
github.com/joho/godotenv
```
