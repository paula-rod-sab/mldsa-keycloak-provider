# PQC JWT Integration for Keycloak ![Java](https://img.shields.io/badge/Java-17+-blue) ![Maven](https://img.shields.io/badge/Maven-3.8+-orange)&nbsp;![License](https://img.shields.io/badge/License-MIT-green)

**Post-Quantum Cryptography (PQC) support for JWT tokens in Keycloak using ML-DSA-44.**  
Secure JWT signing and verification with a modular SPI architecture, ready for extension to other PQC algorithms.

---

## Quick Start

```bash
# Clone the repository
git clone https://github.com/yourusername/mldsa-keycloak-provider.git
cd mldsa-keycloak-provider

# Build the JAR
mvn clean package

# Copy to Keycloak providers folder and restart Keycloak
cp target/mldsa-keycloak-provider.jar $KEYCLOAK_HOME/providers/

# Configure Your Realm
Configure your realm to use **ML-DSA-44** for JWT signing.
```

---

## Features

- JWT signing & verification with **ML-DSA-44**  
- Modular SPI design for easy integration of other PQC algorithms  
- Temporary local key management for PoC; production-ready storage recommended  

---

## Extending to Other Algorithms

1. Implement `SignatureProvider` & `SignatureProviderFactory`  
2. Develop signer & verifier contexts  
3. Implement key management classes if needed  

---

## References

- [Keycloak SPI Documentation](https://www.keycloak.org/docs/latest/server_development/#_spi)  
- [NIST PQC Algorithms](https://csrc.nist.gov/projects/post-quantum-cryptography)  
- [DILITHIUM Certificates IETF Draft](https://datatracker.ietf.org/doc/html/draft-ietf-lamps-dilithium-certificates-12)  

---

## License

MIT License
