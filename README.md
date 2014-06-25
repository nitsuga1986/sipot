SIPOT: SIP Open Tester
========
**Herramienta para auditar sistemas VoIP basados en SIP**

## Dependencias: ##
Para poder utilizar esta aplicación se deberá tener instaladas las siguientes dependencias y estar vinculadas en PYTHONPATH para su importación.

### 39 Peers ###
> "_The 39 Peers project aims at implementing an open-source peer-to-peer Internet telephony software using the Session Initiation Protocol (P2P-SIP) in the Python programming language._"

*   **Link:** [39 Peers](https://pypi.python.org/pypi/multitask/) .
*   **Licencia:** GNU/GPL.
*   **Uso:** Librería básica del protocolo SIP.

### Multitask 0.2.0 ###
> "_Cooperative multitasking and asynchronous I/O using generators_"

*   **Link:** [Multitask 0.2.0](https://pypi.python.org/pypi/multitask/).
*   **Licencia:** MIT License.
*   **Uso:** Para generar tareas simultaneas sin bloquera los sockets.


## Descripción general: ##
La presente herramienta propone el uso de la librerìa de 39Peers desarrollada por Kundan Singh para el desarrollo de una herramienta interactiva que permita auditar sistemas VoIP basados en SIP.
1.   **Flooding**
2.   **Fuzzing**
3.   **Spoofing**

### Opciones básicas ###
#### Generales ####
    --version             show program's version number and exit
    -h, --help            show this help message and exit
    -v, --verbose         enable verbose mode for this module
    -V, --verbose-all     enable verbose mode for all modules

#### Opciones de red ####
    --transport=TRANSPORT
                        the transport type is one of "udp", "tcp" or "tls".
                        Default is "udp"
    --int-ip=INT_IP     listening IP address for SIP and RTP. Use this option
                        only if you wish to select one out of multiple IP
                        interfaces. Default "0.0.0.0"
    --port=PORT         listening port number for SIP UDP/TCP. TLS is one more
                        than this. Default is 5092
    --fix-nat           enable fixing NAT IP address in Contact
    --max-size=MAX_SIZE
                        size of received socket data. Default is 4096
    --interval=INTERVAL
                        The interval argument specifies how often should the
                        sock be checked for close, default is 180 s
#### Opciones básicas del protocolo SIP ####

    --username=USERNAME
                        username to use in my SIP URI and contacts. Default is
                        "nitsuga"
    --pwd=PASSWORD      set this if REGISTER requires pasword authentication.
                        Default is empty "" to not set.  A list of passwords
                        can be provided in the form of pwd1,pwd1,...,etc.
    --domain=DOMAIN     domain portion of my SIP URI. Default is to use local
                        hostname, which is "nitsuga-CX61-laptop"
    --proxy=PROXY       IP address of the SIP proxy to use. Default is empty
                        "" to mean disable outbound proxy
    --to=TO             the target SIP address, e.g., '"Henry Sinnreich"
                        <sip:henry@iptel.org>'. This is mandatory
    --from=FROMADDR     the user SIP address, e.g., '"Henry Sinnreich"
                        <sip:henry@iptel.org>'.
    --uri=URI           the target request-URI, e.g., "sip:henry@iptel.org".
                        Default is to derive from the --to option
    --register          enable user register befor sending messages
    --reg-username=REG_USERNAME
                        username used to for register. If not porvided
                        --username will be used.
    --reg-ip=REGISTRAR_IP
                        Registrar IP. If not provided is extracted from to
                        address: A registrar is a server that accepts REGISTER
                        requests and places the information it receives in
                        those requests into the location service for the
                        domain it handles.
    --register-interval=REGISTER_INTERVAL
                        registration refresh interval in seconds. Default is
                        3600
    --reg-refresh       Auto refresh registration. The refresh argument can be
                        supplied to automatically perform registration refresh
                        before the registration expires. Do not perform
                        refresh by default.
#### Selección del modulo a utilizar ####
    -M SIPOT_MODE, --sipot-mode=SIPOT_MODE
                        flooding / fuzzing / spoofing. set the mode of attack
                        for SIPOT. Default is flooding.
### Ejemplos de prueba ###
Registrar una extensión SIP:
`python sipot.py --register --username 109 --pwd abc123 --reg-ip 192.168.56.77`

## Módulos: ##
La presente herramienta consta de (3) módulos principales, con sus diferentes opciones, para explotar tres de los ataques más comunes realizados a servidores SIP:

### Flooding ###
_**Estado:** En desarrollo._
#### Opciones ####
    --flood-number=FLOOD_NUM
                        Sets the number of messages to be sent by flooding
                        mode. Default is 500.
    --flood-method=FLOOD_METHOD
                        Set the method to flood. Default is REGISTER.
    --flood-msg-file=FLOOD_MSG_FILE
                        Provide a message from file to flood.
    --no-modify-ext     If not specified, extentions will be modified in each
                        message flooded. To generate extentions options --ext-
                        dictionary &--ext-range  will be used.

#### Ejemplos ####
Flood 500 Msg to 192.168.56.77:
`python sipot.py --sipot-mode flooding --to sip:109@192.168.56.77:5060 --flood-number 500`
Flood 500 Msg from File to 192.168.56.77:
`python sipot.py --sipot-mode flooding --to sip:109@192.168.56.77:5060 --flood-number 500 --flood-msg-file sipot_flood_this.txt`
Flood 500 Msg to 192.168.56.77 changing extentions with dictionary:
`python sipot.py --sipot-mode flooding --to sip:109@192.168.56.77:5060 --flood-number 500 --ext-dictionary sipot_ext_dict_example.txt` 


### Fuzzing ###
_**Estado:** No desarrollado aún._

### Spoofing ###
_**Estado:** No desarrollado aún._






[Markup Preview](http://github-markup.dfilimonov.com/)







