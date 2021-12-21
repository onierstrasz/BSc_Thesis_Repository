# Jenny in Wonderland - Exploring the Difficulties of Symmetric Encryption
This repository contains my Bachelor thesis as well as the related data.
I conducted the project in automn semester 2021 at the University of Bern 
as part of the Software Composition Group lead by Prof. Dr. Oscar Nierstrasz.
I was supervised by Dr. Mohammad Ghafari and Mohammadreza Hazhirpasand.

## Abstract
Recent research revealed that a wide range of cryptography libraries lacked usability.
Developers therefore misused them and produced insecure applications.
A commonly observed source of obstacles was lack of documentation quality.
Programmers consult other resources (*i.e.*, Stack Overflow) if they do not find the required information or code examples in the official documentation.


In this context, we aimed for an investigation on API level to further clarify developers' obstacles.
We focused on symmetric-encryption-related APIs from Java Cryptography Architecture (JCA) library, in particular the Cipher class.
We analyzed the content of 150 threads from Stack Overflow to identify the issues programmers faced when working with these APIs as well as common forms of API misuse causing security risks.
We also sought links between these problems and JCA's documentation by formulating questions for each issue and seeking the answers in the documentation.


We observed that most of the identified issues related to the generation of parameters (*e.g.*, keys) or instantiating a Cipher object (*e.g.*, specifying encryption mode).
About 20% of issues were discussed regarding security.
However, only 24 threads did not contain any potential security risks.
The identified risks mainly related to the use of unsafe encryption modes and constant/static values as a key or initialization vector.
We were able to reduce the issues and security risks to 64 questions.
Most of them (> 84%) were at least partly covered by the documentation.
We concluded that most issues and cases of misuse could have been prevented if the original poster had read and understood the documentation.
However, JCA's documentation spreads over several documents, and locating the required piece of information might therefore be difficult.
Additionally, programmers may lack the required domain knowledge and find documentation hard to understand.
As this study revealed several JCA-specific obstacles relating to its documentation or the library design, we recommend that future research continues evaluating cryptography libraries on API level.
