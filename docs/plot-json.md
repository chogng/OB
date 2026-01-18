# plot.json 规范（v1）

该文件用于让 OriginBridge（或其 Python worker）在仅拿到 `csv` 的情况下，知道：
1) 用哪个 CSV（以及它在哪里）。
2) CSV 哪些列组成一对 (X,Y)。
3) 多对 XY 画在同一张图还是多张图，以及（可选）使用哪个 `.otpu` 模板。

默认约定：`plot.json` 放在解压后的包根目录（与 `*.csv` 同级），文件编码 UTF-8。

## 顶层字段

- `version`（必填，number）：规范版本号，当前为 `1`。
- `csv`（可选，string）：CSV 相对路径（相对包根目录）或绝对路径。省略时由程序按策略自动选择一个 `*.csv`。
- `template`（可选，string）：图模板路径（`.otp/.otpu`），相对包根目录或绝对路径。省略时使用 Origin 默认模板/默认绘图行为。
- `graphs`（必填，array）：要生成的图列表。
- `output`（可选，object）：输出控制（项目名、导出图片等；v1 先定义字段，具体支持程度以实现为准）。

## graphs[i]

- `name`（可选，string）：图名称（用于日志/导出命名）。
- `template`（可选，string）：覆盖顶层 `template`。
- `layer`（可选，number）：目标图层索引（从 `0` 开始）；用于多层模板。默认 `0`。
- `series`（必填，array）：曲线列表。

## series[j]

- `x`（必填，ColumnRef）：X 列引用。
- `y`（必填，ColumnRef）：Y 列引用。
- `label`（可选，string）：曲线名称（用于图例/导出）。
- `type`（可选，number|string）：绘图类型。建议使用 Origin `plotxy`/绘图 API 的类型码（例如 `202` 表示 Line+Symbol）。省略时默认 `202`。

## ColumnRef

列引用支持两种写法：

1) **数字**：`0` 基列序号（第 1 列写 `0`，第 2 列写 `1`，以此类推）
2) **字符串**：CSV 表头名称（精确匹配，建议避免重复列名）

## output（预留）

- `projectName`（可选，string）：输出 `.opju` 文件名，默认 `originbridge.opju`
- `export`（可选，array）：导出图片/矢量的配置（格式、尺寸、文件名等；后续迭代）

## 示例

### 1）每对都有自己的 X（X1-Y1、X2-Y2），画到同一张图

```json
{
  "version": 1,
  "csv": "result.csv",
  "template": "my_plot_template.otpu",
  "graphs": [
    {
      "name": "AllCurves",
      "layer": 0,
      "series": [
        { "x": "x1", "y": "y1", "label": "curve1" },
        { "x": "x2", "y": "y2", "label": "curve2" }
      ]
    }
  ]
}
```

### 2）同一个 X + 多列 Y（X, Y1, Y2），画到同一张图（用列序号）

```json
{
  "version": 1,
  "csv": "result.csv",
  "graphs": [
    {
      "name": "XYY",
      "series": [
        { "x": 0, "y": 1, "label": "Y1" },
        { "x": 0, "y": 2, "label": "Y2" }
      ]
    }
  ]
}
```

