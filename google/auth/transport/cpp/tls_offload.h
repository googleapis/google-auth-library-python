#include <cstddef>

typedef int (*SignFunc)(unsigned char *sig, size_t *sig_len, const unsigned char *tbs, size_t tbs_len);

class CustomKey {
 public:
  explicit CustomKey(SignFunc sign_func): sign_func_(sign_func) {}
 
  virtual bool Sign(unsigned char *sig, size_t *sig_len,
            const unsigned char *tbs, size_t tbs_len) {
    return sign_func_(sig, sig_len, tbs, tbs_len);
  }
 
 public:
  SignFunc sign_func_;
};