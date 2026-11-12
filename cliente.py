import hashlib
import ipaddress
import os
import socket
import struct
import zlib

INFO, DATA, ACK, ERR, FIM, NACK = 2, 3, 4, 5, 6, 7

CAB_INFO = struct.Struct("!BIQ16s")
CAB_DATA = struct.Struct("!BIIH")
CAB_CTRL = struct.Struct("!BI")

TIMEOUT_GET = 2.0
TENTATIVAS_GET = 5
TIMEOUT_DADOS = 10.0
PASTA_SAIDA = "recebidos"


def pedir_arquivo(sock, servidor, nome):
    pedido = f"GET /{nome}".encode("utf-8")
    for tentativa in range(1, TENTATIVAS_GET + 1):
        print(f"-> GET /{nome} para {servidor[0]}:{servidor[1]} (tentativa {tentativa})")
        sock.sendto(pedido, servidor)
        try:
            resposta, origem = sock.recvfrom(2048)
        except (socket.timeout, ConnectionResetError):
            continue
        if resposta and resposta[0] in (INFO, ERR):
            return resposta, origem
    return None, None


def receber_blocos(sock, transf, total, descartar):
    blocos = {}
    passo = max(1, total // 10)
    while True:
        try:
            pacote, origem = sock.recvfrom(2048)
        except socket.timeout:
            print("Tempo esgotado: o servidor parou de enviar.")
            return blocos
        except ConnectionResetError:
            continue
        if origem != transf or not pacote:
            continue

        tipo = pacote[0]
        if tipo == INFO:
            sock.sendto(CAB_CTRL.pack(ACK, 0), transf)
        elif tipo == FIM:
            sock.sendto(CAB_CTRL.pack(ACK, total + 1), transf)
            return blocos
        elif tipo == DATA and len(pacote) >= CAB_DATA.size:
            _, seq, crc, tam = CAB_DATA.unpack_from(pacote)
            dados = pacote[CAB_DATA.size:]

            if seq in descartar:
                descartar.remove(seq)
                print(f"[PERDA SIMULADA] bloco {seq} descartado, nenhum ACK enviado")
            elif len(dados) != tam or zlib.crc32(dados) != crc:
                print(f"[CHECKSUM] bloco {seq} com CRC32 invalido -> NACK {seq}")
                sock.sendto(CAB_CTRL.pack(NACK, seq), transf)
            else:
                if seq not in blocos:
                    blocos[seq] = dados
                    if len(blocos) % passo == 0 or len(blocos) == total:
                        print(f"   recebidos {len(blocos)}/{total} blocos ({len(blocos) * 100 // total}%)")
                sock.sendto(CAB_CTRL.pack(ACK, seq), transf)


def baixar(servidor, nome, descartar):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(TIMEOUT_GET)
        resposta, transf = pedir_arquivo(sock, servidor, nome)
        if resposta is None:
            print("Servidor nao respondeu.")
            return
        if resposta[0] == ERR:
            print(f"ERRO DO SERVIDOR: {resposta[1:].decode('utf-8', 'replace')}")
            return

        _, total, tamanho, md5_esperado = CAB_INFO.unpack_from(resposta)
        print(f"<- INFO: {tamanho} bytes em {total} blocos")
        sock.sendto(CAB_CTRL.pack(ACK, 0), transf)
        sock.settimeout(TIMEOUT_DADOS)
        blocos = receber_blocos(sock, transf, total, descartar)

    faltando = [s for s in range(1, total + 1) if s not in blocos]
    if faltando:
        print(f"Arquivo incompleto: faltam {len(faltando)} blocos")
        return

    conteudo = b"".join(blocos[s] for s in range(1, total + 1))
    if hashlib.md5(conteudo).digest() != md5_esperado:
        print("Falha de integridade: o MD5 nao confere")
        return

    os.makedirs(PASTA_SAIDA, exist_ok=True)
    caminho = os.path.join(PASTA_SAIDA, os.path.basename(nome))
    with open(caminho, "wb") as f:
        f.write(conteudo)
    print(f"SUCESSO: arquivo salvo em {caminho} (MD5 confere)")


def main():
    while True:
        comando = input("\nDigite @IP:Porta/arquivo (ou 'sair'): ").strip()
        if comando == "sair":
            break
        try:
            endereco, nome = comando.lstrip("@").split("/", 1)
            ip, porta = endereco.split(":")
            servidor = (str(ipaddress.IPv4Address(ip)), int(porta))
        except ValueError:
            print("Formato invalido. Use um IPv4: @192.168.1.10:5000/nome_do_arquivo.ext")
            continue

        print(f"Cliente iniciado. Servidor de destino: {servidor[0]}:{servidor[1]}")
        texto = input("Blocos a descartar (ex: 3,7 ou Enter para nenhum): ")
        try:
            descartar = {int(x) for x in texto.split(",") if x.strip()}
        except ValueError:
            print("Lista invalida, nenhum bloco sera descartado")
            descartar = set()
        if descartar:
            print(f"Simulacao de perda ativa: blocos {sorted(descartar)}")

        baixar(servidor, nome, descartar)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
