from html.parser import HTMLParser

# 解析函数能解析出当前的节点名 属性名和属性值
class MyHTMLParser(HTMLParser):

    def handle_starttag(self, tag, attrs):
        """
        recognize start tag, like <div>
        :param tag:
        :param attrs:
        :return:
        """
        print("Encountered a start tag:", tag)

    def handle_endtag(self, tag):
        """
        recognize end tag, like </div>
        :param tag:
        :return:
        """
        print("Encountered an end tag :", tag)

    def handle_data(self, data):
        """
        recognize data, html content string
        :param data:
        :return:
        """
        print("Encountered some data  :", data)

    def handle_startendtag(self, tag, attrs):
        """
        recognize tag that without endtag, like <img />
        :param tag:
        :param attrs:
        :return:
        """
        print("Encountered startendtag :", tag)
        if attrs is not None:
            print(str(attrs))

    def handle_comment(self, data):
        """

        :param data:
        :return:
        """
        print("Encountered comment :", data)


if __name__ == '__main__':
    parser = MyHTMLParser()
    parser.feed('<html><head><title>Test</title></head>'
                '<body><h1>Parse me!</h1><img src = "xxx" />'
                '<!-- comment --></body></html>')
