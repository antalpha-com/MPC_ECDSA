# CGMP Open-Source Algorithm Library         
[中文版](https://github.com/antalpha-com/MPC_ECDSA/blob/main/docs/README.md)

## Introduction

Multi-Party Computation (MPC) technology is a cryptographic protocol that enables multiple participants to collaborate in computations without revealing their private inputs. MPC signing is a highly secure digital signature scheme used for distributed signing among multiple participants. MPC signing allows multiple participants to safely collaborate in digital signing without worrying about private key exposure, which is crucial for privacy and security-focused applications.

In the field of digital asset management, MPC technology has a wide range of applications, and multi-party signatures and private key sharding will continue to enhance the security of digital assets. In the domain of privacy computing, MPC will be widely applied in fields such as healthcare, finance, and market analysis to ensure data privacy while enabling efficient computation. Additionally, MPC technology will demonstrate extensive potential applications in areas such as voting, smart contracts, and supply chain management. In summary, MPC technology will become a core tool in the digital world to meet the growing demands for privacy and security.

CGMP represents an innovative development in the field of threshold ECDSA protocols, and its technical principles are leading in the industry. It includes a substantial amount of zero-knowledge (zk) verification to resist malicious attacks, ensuring that any computational errors by any party are promptly detected. The protocol has successfully achieved UC security. The paper based on CGMP by Taurus has open-sourced a Go language version of MPC signature implementation, realizing a 6-round pre-signature scheme.

Antalpha's paper based on CGMP has also open-sourced a Go language version of MPC signature implementation. In addition to Taurus, it implements a 3-round pre-pre-signature scheme, saving on communication rounds and providing more options for customers. We also offer better choices in terms of functionality, security, performance, and deployment-friendliness.



## Tutorials

You can deploy, run, and test this project using the following steps. Users can also customize configuration files and scheduling schemes according to their specific requirements.

1. Clone the project and install dependencies. Download this project to your local environment and install the project's dependencies.
2. Modify the cgo pre-compile instructions. This project uses cgo to support the GMP library for large number operations. Modify the appropriate cgo pre-compile instructions according to your operating system.
3. Generate certificate files. You need to generate relevant certificate files to establish TLS connections.
4. Customize configuration files. Users should customize the configuration files according to their specific deployment scenarios.
5. Run the project. After establishing connections according to the configurations, each participant can execute various stages of the MPC protocol under the coordination of the main participant.
6. Test the project. Single-machine and cluster deployment examples are provided for testing, which can assist developers in their testing efforts.
7. Customize execution stage scheduling. This section explains how to add configuration options and modify the logic of the main program. If users need to modify the project's scheduling logic, they can refer to this section.

For detailed instructions on each of the above steps, please refer to the [User Manual](https://github.com/antalpha-com/MPC_ECDSA/blob/main/docs/User%20Manual.md)

## Security Whitepaper

The goal of developing a secure cryptographic algorithm library is to provide robust, reliable, and thoroughly validated cryptographic algorithms. The objective is to ensure the security of the cryptographic algorithm library, including resilience to common attacks, flexibility, openness, transparency, and adherence to best practices. The Security Whitepaper introduces the high-security MPC algorithms used in this project to address private key security concerns. It also outlines the design principles for security, functionality, and performance in the software implementation of the algorithms, ensuring the security and usability of the final algorithm library.

The Security Whitepaper covers the following aspects:

1. Security design of the algorithms.
2. Security design principles for algorithm implementation.
3. Timing attacks and side-channel attacks.
4. Major algorithm functionalities.
5. Security best practices for using the algorithm library.

For more detailed information, please refer to the [Security Whitepaper](https://github.com/antalpha-com/MPC_ECDSA/blob/main/docs/安全白皮书.pdf)

## Community Discussions

This is an open, equal, and inclusive MPC enterprise community where you can connect with other users and contributors, seek help, and get involved. For any issues or requests, you can [report them on GitHub](https://github.com/antalpha-com/MPC_ECDSA/issues) and get answers.

## References

[UC Non-Interactive, Proactive, Threshold ECDSA with Identifiable Aborts](https://eprint.iacr.org/2021/060.pdf)

## License

[Apache License 2.0](https://github.com/antalpha-com/MPC_ECDSA/blob/main/LICENSE)
