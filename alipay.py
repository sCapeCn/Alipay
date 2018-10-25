import json
from datetime import datetime
from tornado.httpclient import HTTPError, AsyncHTTPClient
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from base64 import b64decode, b64encode
from urllib.parse import quote_plus, urlparse, parse_qs
import urllib
import asyncio
import aiohttp


class AliPayException(Exception):
    def __init__(self, code, message):
        self.__code = code
        self.__message = message

    def __repr__(self):
        return u"AliPayException<code:{}, message:{}>".format(self.__code, self.__message)

    def __unicode__(self):
        return u"AliPayException<code:{}, message:{}>".format(self.__code, self.__message)


class ALipayAuthException(AliPayException):
    pass


class LsAlipay:
    """
    本部分主要解决对接支付宝支付部分接口功能，主要流程如下：
    1.在支付宝注册应用，及接入功能注册（参考开发文档 https://docs.open.alipay.com/204/105297）。
    2.根据待接入接口的参数配置资料（参考支付宝开发文档：https://docs.open.alipay.com/api_1/alipay.trade.fastpay.refund.query/）
    ，进行参数配置。
    3.当参数配置完成后，需要利用支付宝提供的密钥工具进行生成私钥和公钥，并将公钥上传至支付宝（支付宝需要使用公钥对商户发来的请求参数
    进行解密，以确保参数没有被篡改）。
    4.利用3中生成的私钥对要发送的url参数进行签名，因为签名也是即将to支付宝的参数的一部分。
    5.待参数发送至支付宝后，支付宝会返回结果，此时需要对返回结果进行解析，并使用公钥进行验签（具体过程参考支付宝开发文档：
    https://docs.open.alipay.com/200/106120），如果是直接支付，则验签成功即可。
    6.如果是异步支付，则需要进行异步验签，此时需要配置参数notify_url（商户需要提供一个post接口，来接收支付宝发来的post请求，
    异步验签流程文档同上）
    总结为：注册应用-获取密钥-参数配置-私钥签名-请求发送-返回值解析-返回值验签 -结果处理
           -------------------------------------------------- -返回值异步验签 - 结果处理
    """
    def __init__(self, app_id, app_private_key='', app_private_key_f='', alipay_public_key='',
                 alipay_public_key_f='', return_url='', app_notify_url='',
                 version='1.0', charset='utf-8', sign_type='RSA2', debug=True):
        """

        :param app_id: # 应用id
        :param app_private_key: 私钥
        :param alipay_public_key:  公钥
        :param return_url: # 返回请求地址
        :param app_notify_url: # 通知请求地址
        :param version:  # 版本号 默认 1.0
        :param charset: # 字符编码 默认 utf-8
        :param sign_type: # 签名方式 默认 RSA2(推荐)
        :param debug: 是否为调试模式
        """
        # 配置公钥和私钥
        if not app_private_key:
            with open(app_private_key_f) as fp:
                self.app_private_key = RSA.importKey(fp.read())
        else:
            self.app_private_key = app_private_key

        if not alipay_public_key:
            with open(alipay_public_key_f) as fp:
                self.alipay_public_key = RSA.import_key(fp.read())
        else:
            self.alipay_public_key = alipay_public_key

        self.format = 'JSON'  # 当前只支持JSON格式
        self.app_id = app_id
        self.charset = charset
        self.sign_type = sign_type
        self.version = version
        self.return_url = return_url
        self.app_notify_url = app_notify_url
        self.app_auth_token = ''  # 授权
        self.client = AsyncHTTPClient()
        self.url = None  # 支付宝访问接口
        self.sign_v = None
        self.biz_content = {}

        # 调用沙箱环境接口
        if debug is True:
            self.__gateway = "https://openapi.alipaydev.com/gateway.do"
        # 调用支付宝正式接口
        else:
            self.__gateway = "https://openapi.alipay.com/gateway.do"

    def build_biz_content(self, **kwargs):
        """
        配置请求参数 biz_content
        :param kwargs:
        :return:
        """
        self.biz_content.update(kwargs)
        biz_content_str = json.dumps(self.biz_content)
        return biz_content_str

    def build_data(self, method, biz_content, return_url=None):
        """
        配置请求参数
        :param method: 接口名称
        :param biz_content:
        :param return_url:
        :return:
        """
        data = {
            "app_id": self.app_id,
            "method": method,
            "charset": self.charset,
            "sign_type": "RSA2",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "version": "1.0",
            "biz_content": biz_content
        }
        if return_url is not None:
            data["notify_url"] = self.app_notify_url
            data["return_url"] = self.return_url
        return data

    def _ordered_data(self, data):
        """
        内部函数，对请求参数进行排序（进行签名时必须）
        :param data:
        :return:
        """
        complex_keys = []
        for key, value in data.items():
            if isinstance(value, dict):
                complex_keys.append(key)

        # 将字典类型的数据dump出来
        for key in complex_keys:
            data[key] = json.dumps(data[key], separators=(',', ':'))
        sorted_result = sorted([(k, v) for k, v in data.items()])
        return sorted_result

    def _sign(self, unsigned_string):
        """

        内部函数，私钥签名函数。
        unsigned_string： 未签名字符串

        通过如下方法生成签名， 具体流程参考：https://docs.open.alipay.com/291/106118

            key = RSA.importKey(open(self._app_private_key_path).read())
            signer = PKCS1_v1_5.new(key)
            signature = signer.sign(SHA.new(unsigned_string.encode("utf8")))
            # base64 编码，转换为unicode表示并移除回车
            sign = base64.encodebytes(signature).decode("utf8").replace("\n", "")

        """
        key = self.app_private_key
        signer = PKCS1_v1_5.new(key)
        signature = signer.sign(SHA256.new(unsigned_string))

        # base64 编码，转换为unicode表示并移除回车
        sign = b64encode(signature).decode("utf8").replace("\n", "")
        return sign

    def get_sign_data(self, data):

        """商户使用_sign，进行请求参数签名，获取签名字符串"""
        data.pop("sign", None)

        # 排序字符串
        unsigned_items = self._ordered_data(data)
        unsigned_string = "&".join("{0}={1}".format(k, v) for k, v in unsigned_items)
        sign = self._sign(unsigned_string.encode("utf-8"))
        self.sign_v = sign
        quoted_string = "&".join("{0}={1}".format(k, quote_plus(v)) for k, v in unsigned_items)

        # 获得最终的订单信息字符串
        signed_string = quoted_string + "&sign=" + quote_plus(sign)
        return signed_string

    def update_url(self, data):
        """
        获取请求路径, 该路径为base64编码后结果
        :param data:
        :return:
        """
        self.url = self.__gateway+'?{data}&sign_type={sign_type}'.format(data=self.get_sign_data(data),
                                                                         sign_type=self.sign_type)
        return self.url

    def verify(self, data, signature):
        """
        用于：签名验证， 即：验签。
        :param data:
        :param signature:
        :return:
        """
        # 生活号异步通知组成的待验签串里需要保留sign_type参数。
        if 'sign_type' in data:
            data.pop('sign_type')  # 移除sign_type
        if 'sign' in data:
            data.pop('sign')
        unsigned_items = self._ordered_data(data)  # 对字典中的字段重新排序
        message = "&".join(u"{}={}".format(k, v) for k, v in unsigned_items)  # 重新构建需要签名的字符串
        return self.is_verify_res_good(message, signature)

    def is_verify_res_good(self, raw_content, signature):
        """
        举例：
            如当面付扫码支付获取二维码的返回内容为：{"alipay_trade_precreate_response":{"code":"10000",
            "msg":"Success","out_trade_no":"6141161365682511",
            "qr_code":"https:\/\/qr.alipay.com\/bax03206ug0kulveltqc80a8"},
            "sign":"VrgnnGgRMNApB1QlNJimiOt5ocGn4a4pbXjdoqjHtnYMWPYGX9AS0ELt8YikVAl6LPfsD7hjSaJoBE="}

            则待验签字段为：{"code":"10000","msg":"Success","out_trade_no":"6141161365682511",
                        "qr_code":"https:\/\/qr.alipay.com\/bax03206ug0kulveltqc80a8"}
        :param raw_content: 支付宝返回结果
        :param signature: 签名
        :return:
        """
        key = self.alipay_public_key  # 支付宝提供的公钥
        signer = PKCS1_v1_5.new(key)
        digest = SHA256.new()
        digest.update(raw_content.encode("utf8"))
        # 对支付宝返回的参数，移除sign_type，sign，排序后再次用支付宝的公钥签名，
        # 将签名结果与支付宝返回的sign进行校验，如下操作，比对签名
        if signer.verify(digest, b64decode(signature.encode("utf8"))):
            return True
        return False

    async def _request(self):
        """
        # 异步调用支付宝接口，获取支付结果
        :return:
        """
        async with aiohttp.ClientSession() as session:
            async with session.get(self.url) as response:
                return await response.text()

    def get(self, response_type, data, retries=0):
        """
        :param response_type: 接口类型，*_*_response
        :param data: url所需数据
        :param retries: 尝试次数
        :return:
        """
        self.url = self.update_url(data)
        loop = asyncio.get_event_loop()
        response = None
        for _ in range(retries):
            try:
                response = loop.run_until_complete(self._request())
            except HTTPError:
                continue
        loop.close()
        if response:
            temp_res = json.loads(response)
            result = temp_res[response_type]
            return result
        else:
            raise AliPayException(code=400, message='')

    def post(self, notify=''):
        """
        异步验签接口， notify为商户收到支付宝的通知。
        :param notify:
        :return: true or false
        """
        try:
            params = urllib.parse.unquote(notify).split('?')[1]
            temp = params.split('&')
        except Exception as e:
            raise e
        temp_dict = {}
        for idx in temp:
            temp_dict[idx.split('=')[0]] = idx.split('=')[1]
        sign = temp_dict.get('sign')
        res_check = self.verify(temp_dict, sign)
        return res_check


def ls_alipay_api(app_id, method, app_private_key='', app_private_key_f='', alipay_public_key='',
                  alipay_public_key_f='', return_url='', app_notify_url='',
                  version='1.0', charset='utf-8', sign_type='RSA2', **kwargs):
    """
        :param app_id:
        :param method:
        :param app_private_key: 私钥字符串 格式为前缀+ 内容 +后缀
        :param alipay_public_key: 公钥字符串 格式为前缀+ 内容 +后缀
        :param app_private_key_f: 私钥证书导入文件格式
        :param alipay_public_key_f: 公钥证书导入文件格式
        :param return_url:
        :param app_notify_url:
        :param version:
        :param charset:
        :param sign_type:
        :param kwargs: 放入 biz_content的非必需参数
        :return:
        """

    if not app_id or not method:
        raise Exception('parameters error')
    response_type = method.replace('.', '_')+'_response'
    ap = LsAlipay(app_id, app_private_key_f=app_private_key_f, app_private_key=app_private_key,
                  alipay_public_key=alipay_public_key, alipay_public_key_f=alipay_public_key_f, return_url=return_url,
                  app_notify_url=app_notify_url,
                  version=version, charset=charset, sign_type=sign_type)

    the_biz = ap.build_biz_content(**kwargs)

    # 组装数据
    the_data = ap.build_data(method, the_biz)

    # 请求发送
    res = ap.get(response_type, the_data, retries=3)

    if "sign" not in res.keys():
        raise AliPayException(
            code=res.get('code', '0'),
            message=res
        )
    # 同步支付验签
    sign = res.pop('sign', None)

    check_sign_res = (ap.verify(res, sign))
    if not check_sign_res:
        raise AliPayException(code=res.get('code', '0'),
                              message=res
                              )
    return res


if __name__ == '__main__':
    res = ls_alipay_api("2016092200567067", 'alipay.trade.fastpay.refund.query',
                        app_private_key_f='./rsa_private_key.pem', alipay_public_key_f='./rsa_public_key.pem',
                        order_no="20180427000000001000000001")

    print(res)








