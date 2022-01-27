const crypto = require('crypto');
const buffer = require('buffer');
const _ = require('lodash');


module.exports = function verifyPassword (password, hashSettings, callback) {
    const hashValue = _.get(hashSettings, 'hash.value');
    const hashEncoding = _.get(hashSettings, 'hash.encoding', 'base64');
    const hashBuffer = Buffer.from(hashValue, hashEncoding);
    

    const saltValue = _.get(hashSettings, 'salt.value');
    const saltEncoding = _.get(hashSettings, 'salt.encoding', 'ascii');
    const saltBuffer = Buffer.from(saltValue, saltEncoding);

    const costFactor = _.get(hashSettings, 'costfactor');
    const blockSize = _.get(hashSettings, 'blocksize');
    const parallelization = _.get(hashSettings, 'parallelization');
    const keyLength = _.get(hashSettings, 'keylength');
    const passwordEncoding = _.get(hashSettings, 'password.encoding', 'utf16le');
    const passwordBuffer = Buffer.from(password, passwordEncoding);    
    
    
    const params = {       
        'N': costFactor,
        'r': blockSize,
        'p': parallelization,
        'maxmem': costFactor * blockSize * 256 
    }
    
    crypto.scrypt(passwordBuffer, saltBuffer, keyLength, params, (err, calculatedHashBuffer) => {
        if (err) {
          callback(err);
        }
        console.log("Current hash " , hashBuffer.toString(hashEncoding));
        console.log("Calculated hash " , calculatedHashBuffer.toString(hashEncoding));

        try {
          const isValidPassword = crypto.timingSafeEqual(
            calculatedHashBuffer,
            hashBuffer,
          );
          console.log("isValidPassword" , isValidPassword);
          callback(null, isValidPassword);
        } catch (err) {
          const message = _.get(err, 'message', '').toLowerCase();    
          if (_.includes(message, 'buffers must have the same length')) {
            callback(null, false);
          } else {
            callback(err);
          }
        }
    
      });


}