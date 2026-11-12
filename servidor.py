import hashlib
import os
import selectors
import socket
import struct
import time
import zlib

PORTA = 5000
PASTA = "arquivos"
TIMEOUT = 0.5
ATRASO = 0.0

TAM_DADOS = 1400
MAX_TENTATIVAS = 20
TENTATIVAS_FIM = 5

INFO, DATA, ACK, ERR, FIM, NACK = 2, 3, 4, 5, 6, 7

CAB_INFO = struct.Struct("!BIQ16s")
CAB_DATA = struct.Struct("!BIIH")
CAB_CTRL = struct.Struct("!BI")

sel = selectors.DefaultSelector()


def log(msg):
    print(msg, flush=True)


def resolver_caminho(pedido):
    pasta_base = os.path.realpath(PASTA)
    nome = pedido.strip().lstrip("/\\")
    if "\x00" in nome:
        return None
    alvo = os.path.realpath(os.path.join(pasta_base, nome))
    try:
        comum = os.path.commonpath([alvo, pasta_base])
    except ValueError:
        return None
    if os.path.normcase(comum) != os.path.normcase(pasta_base):
        return None
    return alvo


def calcular_md5(caminho):
    h = hashlib.md5()
    with open(caminho, "rb") as f:
        for pedaco in iter(lambda: f.read(1 << 20), b""):
            h.update(pedaco)
    return h.digest()


def enviar_erro(sock, cliente, mensagem):
    log(f"[{cliente[0]}:{cliente[1]}] ERRO -> {mensagem}")
    sock.sendto(bytes([ERR]) + mensagem.encode("utf-8"), cliente)


class Transferencia:
    def __init__(self, cliente, caminho, nome):
        self.cliente = cliente
        self.caminho = caminho
        self.rotulo = f"{cliente[0]}:{cliente[1]} {nome}"
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("", 0))
        self.sock.setblocking(False)
        self.arquivo = open(caminho, "rb")

        tamanho = os.path.getsize(caminho)
        self.total = (tamanho + TAM_DADOS - 1) // TAM_DADOS
        self.passo = max(1, self.total // 10)
        md5 = calcular_md5(caminho)
        log(f"[{self.rotulo}] {tamanho} bytes em {self.total} blocos, md5={md5.hex()}, "
            f"porta de envio {self.sock.getsockname()[1]}")

        self.seq = 0
        self.pacote = CAB_INFO.pack(INFO, self.total, tamanho, md5)
        self.max_tentativas = MAX_TENTATIVAS
        self.tentativa = 0
        self.retransmissoes = 0
        self.prazo = None
        self.proximo_envio = None
        self.inicio = time.monotonic()
        self.enviar()

    def enviar(self):
        self.tentativa += 1
        self.sock.sendto(self.pacote, self.cliente)
        self.prazo = time.monotonic() + TIMEOUT
        self.proximo_envio = None

    def proximo_evento(self):
        return self.proximo_envio if self.proximo_envio is not None else self.prazo

    def avancar(self):
        self.retransmissoes += self.tentativa - 1
        if self.seq == self.total + 1:
            duracao = time.monotonic() - self.inicio
            log(f"[{self.rotulo}] CONCLUIDO em {duracao:.2f}s, {self.retransmissoes} retransmissoes")
            return False
        if 1 <= self.seq and (self.seq % self.passo == 0 or self.seq == self.total):
            log(f"[{self.rotulo}] {self.seq * 100 // self.total}% ({self.seq}/{self.total})")

        self.seq += 1
        self.tentativa = 0
        if self.seq <= self.total:
            dados = self.arquivo.read(TAM_DADOS)
            self.pacote = CAB_DATA.pack(DATA, self.seq, zlib.crc32(dados), len(dados)) + dados
        else:
            self.pacote = CAB_CTRL.pack(FIM, self.seq)
            self.max_tentativas = TENTATIVAS_FIM

        if ATRASO:
            self.prazo = None
            self.proximo_envio = time.monotonic() + ATRASO / 1000
        else:
            self.enviar()
        return True

    def receber(self):
        try:
            resposta, origem = self.sock.recvfrom(64)
        except (BlockingIOError, ConnectionResetError):
            return True
        if origem != self.cliente or len(resposta) < CAB_CTRL.size:
            return True
        tipo, num = CAB_CTRL.unpack_from(resposta)
        if num != self.seq or self.prazo is None:
            return True
        if tipo == ACK:
            return self.avancar()
        if tipo == NACK:
            log(f"[{self.rotulo}] NACK {self.seq} (checksum invalido no cliente) -> retransmitindo")
            return self.retransmitir()
        return True

    def retransmitir(self):
        if self.tentativa >= self.max_tentativas:
            if self.seq == self.total + 1:
                log(f"[{self.rotulo}] ACK do FIM nao recebido (cliente provavelmente ja encerrou)")
            else:
                log(f"[{self.rotulo}] bloco {self.seq} sem ACK apos {self.max_tentativas} tentativas, abortando")
            return False
        self.enviar()
        return True

    def verificar_tempo(self, agora):
        if self.proximo_envio is not None:
            if agora >= self.proximo_envio:
                self.enviar()
            return True
        if agora < self.prazo:
            return True
        log(f"[{self.rotulo}] TIMEOUT aguardando ACK {self.seq} "
            f"(tentativa {self.tentativa}/{self.max_tentativas}) -> retransmitindo")
        return self.retransmitir()

    def fechar(self):
        self.sock.close()
        self.arquivo.close()


def atender_pedido(sock, transferencias):
    try:
        dados, cliente = sock.recvfrom(2048)
    except (BlockingIOError, ConnectionResetError):
        return
    texto = dados.decode("utf-8", "replace").strip()
    log(f"[{cliente[0]}:{cliente[1]}] requisicao: {texto}")
    if not texto.startswith("GET "):
        enviar_erro(sock, cliente, "400 Requisicao invalida, use: GET /nome_do_arquivo")
        return
    pedido = texto[4:]
    caminho = resolver_caminho(pedido)
    if caminho is None:
        log(f"[SEGURANCA] path traversal bloqueado: '{pedido}' de {cliente[0]}:{cliente[1]}")
        enviar_erro(sock, cliente, "403 Acesso negado: o arquivo esta fora da pasta permitida")
        return
    if not os.path.isfile(caminho):
        enviar_erro(sock, cliente, f"404 Arquivo nao encontrado: {pedido}")
        return
    if any(t.cliente == cliente and t.caminho == caminho for t in transferencias.values()):
        return
    try:
        t = Transferencia(cliente, caminho, os.path.basename(caminho))
    except OSError as e:
        enviar_erro(sock, cliente, f"500 Erro ao abrir o arquivo: {e.strerror}")
        return
    transferencias[t.sock] = t
    sel.register(t.sock, selectors.EVENT_READ, data=t)


def encerrar(transferencias, t):
    sel.unregister(t.sock)
    t.fechar()
    del transferencias[t.sock]


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", PORTA))
    sock.setblocking(False)
    sel.register(sock, selectors.EVENT_READ, data=None)
    log(f"Servidor UDP escutando em 127.0.0.1:{PORTA}, "
        f"servindo a pasta {PASTA}")

    transferencias = {}
    try:
        while True:
            agora = time.monotonic()
            timeout = 1.0

            for t in transferencias.values():
                    timeout = min(timeout, max(0.0, t.proximo_evento() - agora))

            eventos = sel.select(timeout)

            for chave, _ in eventos:
                if chave.data is None:
                    atender_pedido(sock, transferencias)
                elif chave.fileobj in transferencias and not chave.data.receber():
                    encerrar(transferencias, chave.data)

            agora = time.monotonic()

            for t in list(transferencias.values()):
                if not t.verificar_tempo(agora):
                    encerrar(transferencias, t)

    except KeyboardInterrupt:
        log("Servidor encerrado")
    finally:
        for t in list(transferencias.values()):
            encerrar(transferencias, t)
        sel.unregister(sock)
        sel.close()
        sock.close()


if __name__ == "__main__":
    main()
