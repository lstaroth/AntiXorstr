<h1 align="center">
<span>AntiXorstr</span>
</h1>
<p align="center">
    <a href="./README.md">English</a> | 中文介绍
</p>
<p align="center">
    <em>枚举和自动解密那些使用c++模板技巧实现的加密字符串，无需关注加密字符串的算法实现</em>
</p>

### 原理

利用C++模板技巧实现字符串的编译期加密存在难以绕过的固有模式，可以被特定规则捕捉，本插件利用这一特点首先对该特征进行识别，筛选出可疑特征后利用unicorn模拟执行，使用其原本的解密代码进行加密字符串还原，因此无需关心其加密算法设计。

### 安装

AntiXorstr支持x86和x64二进制文件，并且可以在任何IDA版本 >= 7.0上运行。安装插件只需将最新版本的代码复制到您的IDA安装目录下的`plugins\`文件夹中即可，记得安装python 3.9(测试过)，以及`requirements`中指定的库

### 例子

```c++
void SampleEncryped()
{
    std::cout << OBFUSCATED("starry") << std::endl;
    std::cout << OBFUSCATED("Softrib") << std::endl;
    std::cout << OBFUSCATED("arlboro") << std::endl;
    std::cout << OBFUSCATED("Angus") << std::endl;
    std::cout << OBFUSCATED("Estrus") << std::endl;
    std::cout << OBFUSCATED("Overbearing") << std::endl;
    std::cout << OBFUSCATED("Monologue") << std::endl;
    std::cout << OBFUSCATED("hushnoo") << std::endl;
    std::cout << OBFUSCATED("Transparent") << std::endl;
    std::cout << OBFUSCATED("Grind") << std::endl;
}
```

1. 使用来自[andrivet/ADVobfuscator](https://github.com/andrivet/ADVobfuscator)的字符串编译期加密

   ![](ADVobfuscator.png)

2. 使用来自[JustasMasiulis/xorstr](https://github.com/JustasMasiulis/xorstr)的字符串编译期加密

   ![](xorstr.png)

### 注意

本插件无法对如VMP保护过后的程序进行识别，请确认需要分析的函数未被混淆

### 待办(未排序)

- 支持Shellcode
- 识别能力增强
- 支持更多架构
- 代码优化

### 感谢

[erocarrera/pefile](https://github.com/erocarrera/pefile)

[unicorn-engine/unicorn](https://github.com/unicorn-engine/unicorn)

[andrivet/ADVobfuscator](https://github.com/andrivet/ADVobfuscator)

[JustasMasiulis/xorstr](https://github.com/JustasMasiulis/xorstr)
