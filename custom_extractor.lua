
-- custom_extractor.lua
-- 自定义数据提取脚本

-- 创建一个tap
local tap = Listener.new()

-- 输出文件
local output_file = io.open("extracted_data.json", "w")
local packet_count = 0

function tap.packet(pinfo, tvb)
    packet_count = packet_count + 1
    
    -- 提取需要的字段
    local packet_info = {
        number = pinfo.number,
        timestamp = tostring(pinfo.abs_ts),
        src = tostring(pinfo.src),
        dst = tostring(pinfo.dst),
        protocol = pinfo.cols.protocol,
        length = pinfo.len
    }
    
    -- 如果是TCP包，提取额外信息
    local tcp_info = pinfo.cols.info
    if tcp_info then
        packet_info.info = tcp_info
    end
    
    -- 写入JSON格式
    output_file:write(table.concat({
        '{"packet":', packet_count, 
        ',"data":', json_encode(packet_info), '}\n'
    }))
    
    -- 每1000包刷新一次
    if packet_count % 1000 == 0 then
        output_file:flush()
        print("已处理", packet_count, "个数据包")
    end
end

function tap.draw()
    print("数据提取完成，共处理", packet_count, "个数据包")
    output_file:close()
end

-- 简单的JSON编码函数
function json_encode(obj)
    local json_str = "{"
    for k, v in pairs(obj) do
        json_str = json_str .. '"' .. k .. '":"' .. tostring(v) .. '",'
    end
    return json_str:sub(1, -2) .. "}"
end
