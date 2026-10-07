"""AI による探索的診断の支援（任意・既定オフ）。

収集済みの診断結果と巡回URLをもとに、人が確認すべき探索的テストの観点と優先度を提示する
「助言」レイヤー。対象へ新たな通信は送らない（攻撃は行わない）。利用するかどうか、どの
プロバイダ（Claude / Gemini / OpenAI）を使うかは設定で選べる。
"""

from .base import AIConfig, Hypothesis, advise, load_ai_config

__all__ = ["AIConfig", "Hypothesis", "advise", "load_ai_config"]
