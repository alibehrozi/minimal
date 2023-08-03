# Network Module

This directory contains the network module of the project, responsible for handling all communication with the backend server and data retrieval.

## Configuration

Before using the network module, ensure to configure the base URL in the NetworkConnection class.

```java
public class NetworkConnection {
    private static final String BASE_URL = "https://api.example.com/";

    // Other configuration settings...
}
```

## TODO List

To fully implement the network module and enable peer-to-peer (P2P) communication, the following tasks need to be completed:

1. **File Analysis and Rewriting:** Analyze existing files and refactor problematic parts to improve code quality and performance.

2. **Writing Tests:** Write comprehensive tests to validate the functionality of the network module and ensure robustness.

3. **Authentication Part:** Implement the authentication logic to secure communication with the backend server.

4. **Appcheck Part:** Set up necessary security checks to ensure the integrity and authenticity of the app.

5. **Proper Handshake:** Implement a proper handshake mechanism after the connection is established to ensure secure communication.

6. **Authorization Part:** Complete the implementation of the authorization logic to control access to specific features and resources.

7. **End-to-End Encryption:** Add end-to-end encryption for not secure connections with key exchange to protect data during transit.

8. **Adding Server Part on TLS:** Set up the server-side logic to handle TLS connections for P2P communication.

9. **Firewall Hole Punching:** Implement a firewall hole punching mechanism to enable direct communication between clients in different networks.

10. **Connection Management:** Create a mechanism to manage connections, accept new connections, and handle user interactions.

11. **Handshake Between Clients:** Implement a handshake protocol between clients to establish secure and authenticated P2P communication.

## Acknowledgements

The network module is a part of the [Firebase Database](https://firebase.google.com/docs/database) project by [Google](https://www.google.com/). It has been customized and integrated into this project to handle communication with the backend server and data retrieval.
For more information and in-depth documentation about Firebase Database, please refer to the [official Firebase documentation](https://firebase.google.com/docs/database).