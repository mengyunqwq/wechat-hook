#pragma once
#include <string>

namespace WeixinSend
{
    void SendImage(const std::string& wxid, const std::string& imgPath);
    // atlist：真 @ 用。填被 @ 的人的 wxid（多个用英文逗号分隔），对方才会收到提醒。
    // 结构体布局自动校验报告（JSON 文本，供 /Debug/StructCheck 用）
    std::string StructCheckReportJson();

    void SendText(const std::string& wxidorgid, const std::string& msg,
                  const std::string& atlist = std::string());
    void DecodePic(const std::string& enc_pic_path, const std::string& dec_pic_path);
}
