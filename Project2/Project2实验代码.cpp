#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <errno.h>

// BMP文件头结构
typedef struct {
    unsigned short bfType;
    unsigned int bfSize;
    unsigned short bfReserved1;
    unsigned short bfReserved2;
    unsigned int bfOffBits;
} BMPFILEHEADER;

// BMP信息头结构
typedef struct {
    unsigned int biSize;
    int biWidth;
    int biHeight;
    unsigned short biPlanes;
    unsigned short biBitCount;
    unsigned int biCompression;
    unsigned int biSizeImage;
    int biXPelsPerMeter;
    int biYPelsPerMeter;
    unsigned int biClrUsed;
    unsigned int biClrImportant;
} BMPINFOHEADER;

// 读取BMP图像（使用fopen_s替代fopen）
unsigned char* readBMP(const char* filename, BMPFILEHEADER* fileHeader, BMPINFOHEADER* infoHeader) {
    FILE* file = NULL;
    errno_t err = fopen_s(&file, filename, "rb");
    if (err != 0 || file == NULL) {
        printf("无法打开文件: %s (错误码: %d)\n", filename, err);
        return NULL;
    }

    // 读取文件头
    fread(fileHeader, sizeof(BMPFILEHEADER), 1, file);
    if (fileHeader->bfType != 0x4D42) { // "BM"标识检查
        printf("不是有效的BMP文件\n");
        fclose(file);
        return NULL;
    }

    // 读取信息头
    fread(infoHeader, sizeof(BMPINFOHEADER), 1, file);

    // 仅支持24位真彩色
    if (infoHeader->biBitCount != 24) {
        printf("错误：仅支持24位真彩色BMP文件\n");
        fclose(file);
        return NULL;
    }

    // 计算行字节数（4字节对齐）
    int widthBytes = (infoHeader->biWidth * 3 + 3) & ~3;
    int imageSize = widthBytes * abs(infoHeader->biHeight);

    // 分配图像数据内存
    unsigned char* imageData = (unsigned char*)malloc(imageSize);
    if (imageData == NULL) {
        printf("内存分配失败：无法分配图像数据缓冲区\n");
        fclose(file);
        return NULL;
    }

    // 定位到像素数据区
    fseek(file, fileHeader->bfOffBits, SEEK_SET);
    fread(imageData, imageSize, 1, file);
    fclose(file);

    return imageData;
}

// 保存BMP图像（使用fopen_s替代fopen）
int saveBMP(const char* filename, BMPFILEHEADER* fileHeader, BMPINFOHEADER* infoHeader, unsigned char* imageData) {
    FILE* file = NULL;
    errno_t err = fopen_s(&file, filename, "wb");
    if (err != 0 || file == NULL) {
        printf("无法创建文件: %s (错误码: %d)\n", filename, err);
        return 0;
    }

    // 更新文件大小（可选，部分场景需要）
    int widthBytes = (infoHeader->biWidth * 3 + 3) & ~3;
    fileHeader->bfSize = sizeof(BMPFILEHEADER) + sizeof(BMPINFOHEADER) + widthBytes * abs(infoHeader->biHeight);

    // 写入文件头和信息头
    fwrite(fileHeader, sizeof(BMPFILEHEADER), 1, file);
    fwrite(infoHeader, sizeof(BMPINFOHEADER), 1, file);

    // 写入像素数据
    fwrite(imageData, widthBytes * abs(infoHeader->biHeight), 1, file);
    fclose(file);

    return 1;
}

// 嵌入水印（LSB算法）
void embedWatermark(unsigned char* imageData, BMPINFOHEADER* infoHeader, const char* watermark, int watermarkLen) {
    int widthBytes = (infoHeader->biWidth * 3 + 3) & ~3;
    int maxCapacity = (infoHeader->biWidth * abs(infoHeader->biHeight) * 3) / 8; // 3通道，每字节8位

    if (watermarkLen > maxCapacity) {
        printf("警告：水印过长，实际嵌入长度将被截断为 %d 字节\n", maxCapacity);
        watermarkLen = maxCapacity;
    }

    int bitIndex = 0;
    int byteIndex = 0;
    unsigned char currentByte = watermark[byteIndex];

    // 遍历像素嵌入水印
    for (int i = 0; i < abs(infoHeader->biHeight); i++) {
        for (int j = 0; j < infoHeader->biWidth; j++) {
            int pos = i * widthBytes + j * 3;
            for (int k = 0; k < 3; k++) { // B/G/R通道
                if (byteIndex >= watermarkLen) return;

                // 清除最低位并设置水印位
                imageData[pos + k] &= 0xFE;
                imageData[pos + k] |= (currentByte >> (7 - bitIndex)) & 0x01;

                if (++bitIndex == 8) {
                    bitIndex = 0;
                    currentByte = watermark[++byteIndex];
                }
            }
        }
    }
}

// 提取水印
void extractWatermark(unsigned char* imageData, BMPINFOHEADER* infoHeader, char* watermark, int maxLen) {
    int widthBytes = (infoHeader->biWidth * 3 + 3) & ~3;
    int maxCapacity = (infoHeader->biWidth * abs(infoHeader->biHeight) * 3) / 8;
    if (maxLen > maxCapacity) maxLen = maxCapacity;

    memset(watermark, 0, maxLen + 1); // 确保终止符存在
    unsigned char currentByte = 0;
    int bitIndex = 0, byteIndex = 0;

    // 遍历像素提取水印
    for (int i = 0; i < abs(infoHeader->biHeight); i++) {
        for (int j = 0; j < infoHeader->biWidth; j++) {
            int pos = i * widthBytes + j * 3;
            for (int k = 0; k < 3; k++) { // B/G/R通道
                if (byteIndex >= maxLen) return;

                // 提取最低位
                currentByte |= ((imageData[pos + k] & 0x01) << (7 - bitIndex));
                if (++bitIndex == 8) {
                    bitIndex = 0;
                    watermark[byteIndex++] = currentByte;
                    currentByte = 0;
                }
            }
        }
    }
}

// 水平翻转图像
void flipImageHorizontal(unsigned char* imageData, BMPINFOHEADER* infoHeader) {
    int widthBytes = (infoHeader->biWidth * 3 + 3) & ~3;
    int halfWidth = infoHeader->biWidth / 2;

    for (int i = 0; i < abs(infoHeader->biHeight); i++) {
        for (int j = 0; j < halfWidth; j++) {
            int leftPos = i * widthBytes + j * 3;
            int rightPos = i * widthBytes + (infoHeader->biWidth - 1 - j) * 3;

            // 交换B/G/R通道数据
            for (int k = 0; k < 3; k++) {
                unsigned char temp = imageData[leftPos + k];
                imageData[leftPos + k] = imageData[rightPos + k];
                imageData[rightPos + k] = temp;
            }
        }
    }
}

// 调整对比度（公式：new = factor*(old-128)+128）
void adjustContrast(unsigned char* imageData, BMPINFOHEADER* infoHeader, float contrast) {
    int widthBytes = (infoHeader->biWidth * 3 + 3) & ~3;
    float factor = (259.0f * (contrast + 255.0f)) / (255.0f * (259.0f - contrast));

    for (int i = 0; i < abs(infoHeader->biHeight); i++) {
        for (int j = 0; j < infoHeader->biWidth; j++) {
            int pos = i * widthBytes + j * 3;
            for (int k = 0; k < 3; k++) { // 处理每个通道
                int val = (int)(factor * (imageData[pos + k] - 128) + 128);
                imageData[pos + k] = (unsigned char)(val < 0 ? 0 : (val > 255 ? 255 : val));
            }
        }
    }
}

// 截取图像（返回新图像数据，需外部释放）
unsigned char* cropImage(unsigned char* originalData, BMPINFOHEADER* originalHeader,
    BMPINFOHEADER* croppedHeader, int x, int y, int width, int height) {
    // 边界检查
    if (x < 0 || y < 0 || x + width > originalHeader->biWidth || y + height > abs(originalHeader->biHeight)) {
        printf("错误：截取区域超出图像范围\n");
        return NULL;
    }

    // 初始化新图像头
    *croppedHeader = *originalHeader;
    croppedHeader->biWidth = width;
    croppedHeader->biHeight = originalHeader->biHeight > 0 ? height : -height;

    int originalWidthBytes = (originalHeader->biWidth * 3 + 3) & ~3;
    int croppedWidthBytes = (width * 3 + 3) & ~3;
    size_t croppedImageSize = (size_t)croppedWidthBytes * height;

    // 分配内存
    unsigned char* croppedData = (unsigned char*)malloc(croppedImageSize);
    if (croppedData == NULL) {
        printf("内存分配失败：无法创建截取图像缓冲区\n");
        return NULL;
    }

    // 复制像素数据
    for (int i = 0; i < height; i++) {
        int originalRow = y + i;
        if (originalHeader->biHeight < 0) { // 处理倒序存储的BMP
            originalRow = abs(originalHeader->biHeight) - 1 - y - i;
        }

        size_t originalPos = (size_t)originalRow * originalWidthBytes + x * 3;
        size_t croppedPos = (size_t)i * croppedWidthBytes;
        memcpy(&croppedData[croppedPos], &originalData[originalPos], (size_t)width * 3);
    }

    return croppedData;
}

// 平移图像（返回新图像数据，需外部释放）
unsigned char* translateImage(unsigned char* originalData, BMPINFOHEADER* originalHeader,
    int dx, int dy) {
    int widthBytes = (originalHeader->biWidth * 3 + 3) & ~3;
    size_t imageSize = (size_t)widthBytes * abs(originalHeader->biHeight);

    // 分配内存并初始化为黑色
    unsigned char* translatedData = (unsigned char*)malloc(imageSize);
    if (translatedData == NULL) {
        printf("内存分配失败：无法创建平移图像缓冲区\n");
        return NULL;
    }
    memset(translatedData, 0, imageSize);

    // 平移处理
    for (int i = 0; i < abs(originalHeader->biHeight); i++) {
        for (int j = 0; j < originalHeader->biWidth; j++) {
            int newX = j + dx;
            int newY = i + dy;

            // 检查目标位置有效性
            if (newX >= 0 && newX < originalHeader->biWidth && newY >= 0 && newY < abs(originalHeader->biHeight)) {
                size_t originalPos = (size_t)i * widthBytes + j * 3;
                size_t newPos = (size_t)newY * widthBytes + newX * 3;

                // 复制像素（B/G/R）
                for (int k = 0; k < 3; k++) {
                    translatedData[newPos + k] = originalData[originalPos + k];
                }
            }
        }
    }

    return translatedData;
}

int main() {
    BMPFILEHEADER fileHeader;
    BMPINFOHEADER infoHeader;

    // 1. 读取原始图像
    unsigned char* originalImage = readBMP("D:\\Project2\\Debug\\original.bmp", &fileHeader, &infoHeader);
    if (originalImage == NULL) {
        printf("错误：请确保当前目录存在original.bmp（24位BMP格式）\n");
        system("pause");
        return 1;
    }

    // 2. 定义水印（建议长度不超过图像容量）
    const char* watermarkText = "Confidential_Document_2025";
    int watermarkLen = (int)strlen(watermarkText); // 显式转换size_t到int

    // 3. 创建带水印的图像副本
    int widthBytes = (infoHeader.biWidth * 3 + 3) & ~3;
    size_t imageSize = (size_t)widthBytes * abs(infoHeader.biHeight);

    unsigned char* watermarkedImage = (unsigned char*)malloc(imageSize);
    if (watermarkedImage == NULL) {
        printf("内存分配失败：无法创建水印图像副本\n");
        free(originalImage);
        system("pause");
        return 1;
    }
    memcpy(watermarkedImage, originalImage, imageSize);

    // 4. 嵌入水印
    embedWatermark(watermarkedImage, &infoHeader, watermarkText, watermarkLen);
    saveBMP("watermarked.bmp", &fileHeader, &infoHeader, watermarkedImage);
    printf("[+] 水印已嵌入：watermarked.bmp\n");

    // 5. 提取原始水印验证
    char extractedOriginal[512] = { 0 };
    extractWatermark(watermarkedImage, &infoHeader, extractedOriginal, sizeof(extractedOriginal) - 1);
    printf("[√] 原始水印提取：%s\n", extractedOriginal);

    // 6. 鲁棒性测试：水平翻转
    unsigned char* flippedImage = (unsigned char*)malloc(imageSize);
    if (flippedImage == NULL) {
        printf("内存分配失败：无法创建翻转图像缓冲区\n");
        free(originalImage);
        free(watermarkedImage);
        system("pause");
        return 1;
    }
    memcpy(flippedImage, watermarkedImage, imageSize);
    flipImageHorizontal(flippedImage, &infoHeader);
    saveBMP("flipped.bmp", &fileHeader, &infoHeader, flippedImage);

    char extractedFlipped[512] = { 0 };
    extractWatermark(flippedImage, &infoHeader, extractedFlipped, sizeof(extractedFlipped) - 1);
    printf("[翻转测试] 提取水印：%s\n", extractedFlipped);

    // 7. 鲁棒性测试：调整对比度（+80）
    unsigned char* contrastImage = (unsigned char*)malloc(imageSize);
    if (contrastImage == NULL) {
        printf("内存分配失败：无法创建对比度图像缓冲区\n");
        free(originalImage);
        free(watermarkedImage);
        free(flippedImage);
        system("pause");
        return 1;
    }
    memcpy(contrastImage, watermarkedImage, imageSize);
    adjustContrast(contrastImage, &infoHeader, 80.0f); // 增强对比度
    saveBMP("contrast.bmp", &fileHeader, &infoHeader, contrastImage);

    char extractedContrast[512] = { 0 };
    extractWatermark(contrastImage, &infoHeader, extractedContrast, sizeof(extractedContrast) - 1);
    printf("[对比度测试] 提取水印：%s\n", extractedContrast);

    // 8. 鲁棒性测试：图像截取（中心区域）
    BMPINFOHEADER croppedHeader;
    int cropX = infoHeader.biWidth / 4;
    int cropY = abs(infoHeader.biHeight) / 4;
    int cropW = infoHeader.biWidth / 2;
    int cropH = abs(infoHeader.biHeight) / 2;

    unsigned char* croppedImage = cropImage(watermarkedImage, &infoHeader, &croppedHeader, cropX, cropY, cropW, cropH);
    if (croppedImage != NULL) {
        BMPFILEHEADER croppedFileHeader = fileHeader;
        croppedFileHeader.bfSize = sizeof(BMPFILEHEADER) + sizeof(BMPINFOHEADER) +
            (croppedHeader.biWidth * 3 + 3) / 4 * 4 * abs(croppedHeader.biHeight);

        saveBMP("cropped.bmp", &croppedFileHeader, &croppedHeader, croppedImage);

        char extractedCropped[512] = { 0 };
        extractWatermark(croppedImage, &croppedHeader, extractedCropped, sizeof(extractedCropped) - 1);
        printf("[截取测试] 提取水印：%s\n", extractedCropped);
        free(croppedImage);
    }

    // 9. 鲁棒性测试：图像平移（右移30，下移20）
    unsigned char* translatedImage = translateImage(watermarkedImage, &infoHeader, 30, 20);
    if (translatedImage != NULL) {
        saveBMP("translated.bmp", &fileHeader, &infoHeader, translatedImage);

        char extractedTranslated[512] = { 0 };
        extractWatermark(translatedImage, &infoHeader, extractedTranslated, sizeof(extractedTranslated) - 1);
        printf("[平移测试] 提取水印：%s\n", extractedTranslated);
        free(translatedImage);
    }

    // 10. 释放资源
    free(originalImage);
    free(watermarkedImage);
    free(flippedImage);
    free(contrastImage);

    printf("\n所有测试完成！按任意键退出...\n");
    system("pause");
    return 0;
}