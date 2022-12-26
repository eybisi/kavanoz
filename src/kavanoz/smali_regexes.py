import re
class Regexs:

    def __init__(self):
        self.first_inner_regex = {}

    def set_first_inner_regex(self, rc4_string_var: str):
        # invoke-static v0, Lcom/huge/dragon/DEdEoXwGgUxOmDnIdQiBhAeDwDbFbByQwQfQtYuWk;->meattool(B)Ljava/lang/String;
        # move-result-object v0
        # iput-object v0, v3, Lcom/huge/dragon/DEdEoXwGgUxOmDnIdQiBhAeDwDbFbByQwQfQtYuWk;->XZkYqPfMoCcNtMzDiIpGaYlRuDjFeZfMtPcSq Ljava/lang/String;

        first_inner_first_variant = rf"invoke-static [vp]\d+, L[^;]+;->([^\(]+)\(\w*\)+Ljava/lang/String;\s+" \
                                    "move-result-object [vp]\d+\s+" \
                                    f"iput-object [vp]\d+, [vp]\d+, L[^;]+;->{rc4_string_var} Ljava/lang/String;"

        # invoke-static Lsquare/ivory/purchase/YKxOcNuRkOlYhOySzZjCsYqLcJkYuUlJdTfTqMeMgXuOnUzEjNiSs;->antiquehello()Ljava/lang/StringBuilder;
        # move-result-object v0
        # invoke-static v0, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

        first_inner_second_variant = r"invoke-static L[^;]+;->([^\(]+)\(\w*\)+Ljava/lang/StringBuilder;\s+" \
                                     r"move-result-object [vp]\d+\s+" \
                                     r"invoke-static [vp]\d+, Ljava/lang/String;->valueOf\(Ljava/lang/Object;\)Ljava/lang/String;\s+" \
                                     r"move-result-object [vp]\d+\s+" \
                                     fr"iput-object [vp]\d+, [vp]\d+, L[^;]+;->{rc4_string_var} Ljava/lang/String;"

        first_inner_six_variant = r"invoke-static [vp]\d+, L[^;]+;->([^\(]+)\(\w*\)+Ljava/lang/StringBuilder;\s+" \
                                  r"move-result-object [vp]\d+\s+" \
                                  r"invoke-static [vp]\d+, Ljava/lang/String;->valueOf\(Ljava/lang/Object;\)Ljava/lang/String;\s+" \
                                  r"move-result-object [vp]\d+\s+" \
                                  fr"iput-object [vp]\d+, [vp]\d+, L[^;]+;->{rc4_string_var} Ljava/lang/String;"
        nine = r"invoke-static L[^;]+;->([^\(]+)\(\)+Ljava/lang/StringBuilder;\s+" \
               r"move-result-object [vp]\d+\s+" \
               r"invoke-virtual [vp]\d+, Ljava/lang/StringBuilder;->toString\(\)Ljava/lang/String;\s+" \
               r"move-result-object [vp]\d+\s+" \
               fr"iput-object [vp]\d+, [vp]\d+, L[^;]+;->{rc4_string_var} Ljava/lang/String;"
        # invoke-static Lcom/marine/build/NKlIyWrPrYoKzZyRtDsOnKnJtNkNcEoOePzLtNg;->dressraccoon()Ljava/lang/String;
        # move-result-object v0
        # iput-object v0, v3, Lcom/marine/build/NKlIyWrPrYoKzZyRtDsOnKnJtNkNcEoOePzLtNg;->QFxOwNaMaJqTgNdOhOc Ljava/lang/String;

        first_inner_third_variant = "invoke-static L[^;]+;->([^\(]+)\(\w*\)Ljava\/lang\/String;\s+" \
                                    "move-result-object [vp]\d+\s+" \
                                    f"iput-object [vp]\d+, [vp]\d+, L[^;]+;->{rc4_string_var} Ljava/lang/String;"

        first_inner_seven_variant = "invoke-static [vp]\d+, L[^;]+;->([^\(]+)\(Ljava/lang/String;\)Ljava\/lang\/String;\s+" \
                                    "move-result-object [vp]\d+\s+" \
                                    f"iput-object [vp]\d+, [vp]\d+, L[^;]+;->{rc4_string_var} Ljava/lang/String;"
        ten_variant = r"invoke-static [vp]\d+, L[^;]+;->([^\(]+)\(\[I\)Ljava\/lang\/String;\s+" \
                                    "move-result-object [vp]\d+\s+" \
                                    f"iput-object [vp]\d+, [vp]\d+, L[^;]+;->{rc4_string_var} Ljava/lang/String;"

        #invoke-static {v0}, Lcom/frog/assault/ZQwAlNnFmAdZiOe;->corespy([Ljava/lang/String;)Ljava/lang/String;
        #move-result-object v0
        #iput-object v0, p0, Lcom/frog/assault/ZQwAlNnFmAdZiOe;->OPxNlTsOuSiJtOg:Ljava/lang/String;
        eleven_variant = r"invoke-static [vp]\d+, L[^;]+;->([^\(]+)\(\[Ljava/lang/String;\)Ljava\/lang\/String;\s+" \
                                    r"move-result-object [vp]\d+\s+" \
                                    rf"iput-object [vp]\d+, [vp]\d+, L[^;]+;->{rc4_string_var} Ljava/lang/String;"
        # invoke-static v0, Ljknl/bgdfdntrwerlfwaxohrcyamosg/rathpswbuyyukhdihs/Qreunionscience;->symbolraise(Ljava/lang/Boolean;)Ljava/lang/StringBuffer;
        # move-result-object v0
        # invoke-virtual v0, Ljava/lang/StringBuffer;->toString()Ljava/lang/String;
        # move-result-object v0
        # iput-object v0, v4, Ljknl/bgdfdntrwerlfwaxohrcyamosg/rathpswbuyyukhdihs/Qreunionscience;->Salterrail Ljava/lang/String;
        first_inner_fourth_variant = r"invoke-static [vp]\d+, L[^;]+;->([^\(]+)\(Ljava/lang/Object\)Ljava/lang/StringBuffer;\s+" \
                                     r"move-result-object [vp]\d+\s+" \
                                     r"invoke-virtual [vp]\d+, Ljava/lang/StringBuffer;->toString\(\)Ljava/lang/String;\s+" \
                                     r"move-result-object [vp]\d+\s+" \
                                     fr"iput-object [vp]\d+, [vp]\d+, L[^;]+;->{rc4_string_var} Ljava/lang/String;"

        # invoke-static Lrecall/promote/hidden/IYmMtEjAhYyTpQz;->incomeagain()Ljava/lang/StringBuffer;
        # move-result-object v0
        # invoke-virtual v0, Ljava/lang/StringBuffer;->toString()Ljava/lang/String;
        # move-result-object v0
        # iput-object v0, v3, Lrecall/promote/hidden/IYmMtEjAhYyTpQz;->QOlUeNyKnHtWmHdEnUs Ljava/lang/String;

        first_inner_fifth_variant = r"invoke-static L[^;]+;->([^\(]+)\(\)Ljava/lang/StringBuffer;\s+" \
                                    r"move-result-object [vp]\d+\s+" \
                                    r"invoke-virtual [vp]\d+, Ljava/lang/StringBuffer;->toString\(\)Ljava/lang/String;\s+" \
                                    r"move-result-object [vp]\d+\s+" \
                                    fr"iput-object [vp]\d+, [vp]\d+, L[^;]+;->{rc4_string_var} Ljava/lang/String;"
        # invoke-static v0, Lpousozuqamiyngkkoczbahranxo/efcwgecwerpfesmilxxmkco/tpqbn/Pwrongmatch;->trialalert(Z)Ljava/lang/StringBuilder;
        # move-result-object v0
        # invoke-virtual v0, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;
        # move-result-object v0
        # iput-object v0, v4, Lpousozuqamiyngkkoczbahranxo/efcwgecwerpfesmilxxmkco/tpqbn/Pwrongmatch;->Qtwintattoo Ljava/lang/String;

        first_inner_eight_variant = r"invoke-static [vp]\d+, L[^;]+;->([^\(]+)\(Z\)Ljava/lang/StringBuilder;\s+" \
                                    r"move-result-object [vp]\d+\s+" \
                                    r"invoke-virtual [vp]\d+, Ljava/lang/StringBuilder;->toString\(\)Ljava/lang/String;\s+" \
                                    r"move-result-object [vp]\d+\s+" \
                                    fr"iput-object [vp]\d+, [vp]\d+, L[^;]+;->{rc4_string_var} Ljava/lang/String;"
        self.first_inner_regex["first_variant"] = re.compile(first_inner_first_variant)
        self.first_inner_regex["second_variant"] = re.compile(first_inner_second_variant)
        self.first_inner_regex["third_variant"] = re.compile(first_inner_third_variant)
        self.first_inner_regex["fourth_variant"] = re.compile(first_inner_fourth_variant)
        self.first_inner_regex["fifth_variant"] = re.compile(first_inner_fifth_variant)
        self.first_inner_regex["six_variant"] = re.compile(first_inner_six_variant)
        self.first_inner_regex["seven_variant"] = re.compile(first_inner_seven_variant)
        self.first_inner_regex["eight_variant"] = re.compile(first_inner_eight_variant)
        self.first_inner_regex["nine_variant"] = re.compile(nine)
        self.first_inner_regex["ten_variant"] = re.compile(ten_variant)
        self.first_inner_regex["eleven_variant"] = re.compile(eleven_variant)

    def get_first_inner_regexs(self) -> dict:
        return self.first_inner_regex

    @staticmethod
    def get_encrytion_route_regex() -> re:
        first_encrytion_route = "invoke-virtual [vp]\d+, [vp]\d+, L[^\s]+;->([^\s]+)\(Ljava/lang/String;\)Z"
        return re.compile(first_encrytion_route)

    @staticmethod
    def get_key_class_regex() -> re:
        '''
        iput-object v0, v4, Lsolve/expect/water/DWcJrLbBhZuZeQxRsByOgHrOgEwAb;->PTuCuGcNoJqKpAnWyFoNfHoSj Landroid/content/Context;
        iget-object v0, v4, Lsolve/expect/water/DWcJrLbBhZuZeQxRsByOgHrOgEwAb;->PTuCuGcNoJqKpAnWyFoNfHoSj Landroid/content/Context;
        iget-object v1, v4, Lsolve/expect/water/DWcJrLbBhZuZeQxRsByOgHrOgEwAb;->HLcJdEiQiGcGpHyIwXrTiXuQiLqIaRgGt Ljava/lang/String;
        invoke-static v5, v0, v1, Lsolve/expect/water/GKfMeQmSxLkSzNmFoUhBxJrOjAiRsAyGbThJnQhOkNiRuIxUf;->shrugbalcony(Ljava/lang/String; Landroid/content/Context; Ljava/lang/String;)Z
        move-result v5
        return v5
        '''
        key_class_regex = r"invoke-(virtual|static) ([vp]\d+, ){3,4}(L[^\(]+;)->[^\(]+\(Ljava/lang/String; Landroid/content/Context; Ljava/lang/String;\)Z\s+" \
                          r"move-result [vp]\d+\s+" \
                          r"return [vp]\d+"
        return re.compile(key_class_regex)

    @staticmethod
    def get_second_inner_regex():
        second_inner = "invoke-static L[^\(]+;->([^\(]+)\(\)Ljava/lang/String;"
        return re.compile(second_inner)