#include <fcntl.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <memory>
#include <utility>
#include <vector>
#include "scoped_fd.h"
#include "sys/elf32.h"
#include "sys/elf64.h"

using namespace std;

const Elf64_Xword kElfPhdrTypeMask = 7 << 24;
const Elf64_Xword kElfPhdrTypeHash = 2 << 24;
const int kSha256Sz = 32;
const int kHashSegHeaderSz = 40;
const int kSignatureSz = 256;

int print_certs(shared_ptr<char> data, uint32_t sz) {
  const unsigned char *p = reinterpret_cast<const unsigned char *>(data.get());
  unique_ptr<X509, void (*)(X509 *)> cert(d2i_X509(NULL, &p, sz), X509_free);
  if (!cert) {
    fprintf(stderr, "Unable to parse cert\n");
    return -1;
  }

  char *subj = X509_NAME_oneline(X509_get_subject_name(cert.get()), NULL, 0);
  if (!subj) {
    fprintf(stderr, "Unable to get subject\n");
    return -1;
  }

  vector<char *> ous;
  char *token;
  while ((token = strsep(&subj, "/")) != NULL) {
    if (token[0] == '\0') {
      continue;
    }
    if (strncmp(token, "OU", 2) == 0) {
      ous.push_back(token);
    }
  }
  sort(ous.begin(), ous.end(), strcmp);
  for (auto it = ous.cbegin(); it != ous.cend(); ++it) {
    printf("%s\n", *it);
  }
  OPENSSL_free(subj);

  return 0;
}

static pair<shared_ptr<char>, uint32_t> elf32_find_cert(ScopedFd &fd) {
  Elf32_Ehdr ehdr;
  pair<shared_ptr<char>, uint32_t> ret;
  if (read(fd.get(), &ehdr, sizeof(ehdr)) != sizeof(ehdr)) {
    perror("read");
    return ret;
  }

  Elf32_Phdr phdr;
  Elf32_Word data_off = 0;
  uint32_t data_sz;
  int hash_count = 0;
  for (int i = 0; i < ehdr.e_phnum; ++i) {
    uint32_t poff = ehdr.e_phoff + i * ehdr.e_phentsize;
    if (lseek(fd.get(), poff, SEEK_SET) == -1) {
      perror("lseek");
      return ret;
    }
    if (read(fd.get(), &phdr, sizeof(phdr)) != sizeof(phdr)) {
      perror("read");
      return ret;
    }

    ++hash_count;

    if (!data_off) {
      if ((phdr.p_flags & kElfPhdrTypeMask) == kElfPhdrTypeHash) {
        data_off = phdr.p_offset;
        data_sz = phdr.p_filesz;
      }
    }
  }

  if (!data_off) {
    fprintf(stderr, "No hash segment found\n");
    return ret;
  } else {
    Elf32_Word cert_off =
        data_off + kHashSegHeaderSz + hash_count * kSha256Sz + kSignatureSz;
    if (lseek(fd.get(), cert_off, SEEK_SET) == -1) {
      perror("lseek");
      return ret;
    }
    data_sz -= cert_off - data_off;
    char *data = new char[data_sz];
    if (!data) {
      fprintf(stderr, "OOM");
      return ret;
    }
    if (read(fd.get(), data, data_sz) != data_sz) {
      perror("read");
      return ret;
    }
    ret.first.reset(data);
    ret.second = data_sz;
    return ret;
  }
}

static pair<shared_ptr<char>, uint32_t> elf64_find_cert(ScopedFd &fd) {
  Elf64_Ehdr ehdr;
  pair<shared_ptr<char>, uint32_t> ret;
  if (read(fd.get(), &ehdr, sizeof(ehdr)) != sizeof(ehdr)) {
    perror("read");
    return ret;
  }

  Elf64_Phdr phdr;
  Elf64_Xword data_off = 0;
  uint32_t data_sz;
  int hash_count = 0;
  for (int i = 0; i < ehdr.e_phnum; ++i) {
    uint32_t poff = ehdr.e_phoff + i * ehdr.e_phentsize;
    if (lseek(fd.get(), poff, SEEK_SET) == -1) {
      perror("lseek");
      return ret;
    }
    if (read(fd.get(), &phdr, sizeof(phdr)) != sizeof(phdr)) {
      perror("read");
      return ret;
    }

    ++hash_count;

    if (!data_off) {
      if ((phdr.p_flags & kElfPhdrTypeMask) == kElfPhdrTypeHash) {
        data_off = phdr.p_offset;
        data_sz = phdr.p_filesz;
      }
    }
  }

  if (!data_off) {
    fprintf(stderr, "No hash segment found\n");
    return ret;
  } else {
    Elf64_Xword cert_off =
        data_off + kHashSegHeaderSz + hash_count * kSha256Sz + kSignatureSz;
    if (lseek(fd.get(), cert_off, SEEK_SET) == -1) {
      perror("lseek");
      return ret;
    }
    data_sz -= cert_off - data_off;
    char *data = new char[data_sz];
    if (!data) {
      fprintf(stderr, "OOM");
      return ret;
    }
    if (read(fd.get(), data, data_sz) != data_sz) {
      perror("read");
      return ret;
    }
    ret.first.reset(data);
    ret.second = data_sz;
    return ret;
  }
}

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: %s img\n", argv[0]);
    return 1;
  }

  ScopedFd fd(open(argv[1], O_RDONLY));
  if (!fd) {
    perror("open");
    return 1;
  }

  unsigned char ident[EI_NIDENT];
  if (read(fd.get(), ident, sizeof(ident)) != sizeof(ident)) {
    perror("read");
    return 1;
  }
  if (ident[0] != ELFMAG0 || ident[1] != ELFMAG1 || ident[2] != ELFMAG2 ||
      ident[3] != ELFMAG3) {
    fprintf(stderr, "Not elf format\n");
    return 1;
  }

  if (lseek(fd.get(), 0, SEEK_SET) == -1) {
    perror("lseek");
    return 1;
  }

  pair<shared_ptr<char>, uint32_t> data;
  if (ident[EI_CLASS] == ELFCLASS32) {
    data = elf32_find_cert(fd);
  } else if (ident[EI_CLASS] == ELFCLASS64) {
    data = elf64_find_cert(fd);
  } else {
    fprintf(stderr, "Invalid elf format\n");
    return 1;
  }

  if (!data.first) {
    fprintf(stderr, "Failed to get cert data\n");
    return 1;
  }

  if (print_certs(data.first, data.second)) {
    fprintf(stderr, "Failed to print cert\n");
    return 1;
  }

  return 0;
}
