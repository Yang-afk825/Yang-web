"""yang_web.core.multi_stage 子模块 _engine（自 multi_stage.py 拆分，请勿手工重排）。"""

from __future__ import annotations
from ._Base import _Base
from ._Recon import _Recon
from ._Stages import _Stages
from ._SstiStages import _SstiStages

class MultiStageEngine(_Base, _Recon, _Stages, _SstiStages):
    """通用多阶段攻击引擎.

    管线:
      输入 URL → 爬取分析 → 识别阶段类型 → 对应攻击 → 跟随跳转 → ... → Flag
    """
