# Design
## Sequence diagram
![Sequence diagram](https://github.com/Romanyyz/TestTask/blob/main/sequence_diagram.png)
## Flaws and vulnerabilities
- Nonce reuse / Replay: If the nonce is reused, replay attacks are possible.
- ECB leaks: AES-ECB does not hide identical data blocks, making an attacker to be able to analyze the file structure. In a real system, it is recommended to use more secure AES modes.
- Data spoofing and SHA-256: although I verify integrity via SHA-256, an attacker could spoof both the data and the checksum. To protect against this, it is recommended to use GCM mode encryption, which checks the integrity itself.
## Limitations of implementation
At the moment there are problems with the shutdown of services. It is necessary to improve connection management on the server to be able to release resources correctly at session termination.
It is necessary to implement Graceful Shutdown. It is also worth thinking about how to synchronize the release of session resources with asynchronous IO in the kernel.
It is also worth adding manual control of offsets in the received file and its size. This will allow to write to the file in parallel and improve performance.
