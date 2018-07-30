title: 16 个 PHP 设计模式详解
date: 2017-06-06 01:02:03
update: 2017-06-06 01:02:03
author: me
preview: 本课程主要介绍了 16 个设计模式的相关知识，使用 UML 类图形象表示各个类之间的关系，并使用 PHP 实现示例代码。课程内容文字较多，且知识点较为抽象，学习起来有一定的难度。适合作为进阶课程学习。

tags: #可选
    - php
    - 设计模式

---



设计模式（一）
=======
[转自实验楼 https://www.shiyanlou.com/courses/699](https://www.shiyanlou.com/courses/699)
一、实验介绍
------

#### 1.1 实验内容

本课程将和以往的PHP项目课不同，我们不会花大量的时间和精力去实现一个完整的功能或项目，不会和数据库打交道，也不会在去写繁琐的前端代码，而是更专注于纯 PHP 代码的编码技巧和面向对象编程思想，修炼你的内功。课程学习中也有编码部分，虽然都是很简单的代码，但是他们之间的关联关系却不简单，本课程和实验的目的，就是带领大家理清楚各种类之间的关联关系。

实验主要目的是在思想理解层面，希望大家能多花点时间理解与掌握。

课程内容主要参考资料：[图说设计模式— Graphic Design Patterns](https://design-patterns.readthedocs.io/zh_CN/latest/index.html)，维基百科和网络内容，再加上自己的一些理解制作，不足之处还请谅解，引用内容会详细注明出处。

**本实验内容仅做设计模式的简单介绍，并不是非常完整的总结性技术文档，如果你觉得此课程太过简单，可以自行查找更加详细的技术文档学习。**

#### 1.2 实验环境

*   Ubuntu 14.04.5
*   php 7.2
*   mysql 5.5.5.0
*   PHP 7.2

### 1.3 实验知识点

*   UML
*   工厂模式
*   建造者模式
*   单例模式
*   适配器模式
*   桥接模式
*   装饰者模式

### 1.4 适合人群

本课程的内容讲解比较抽象，具有一定的学习难度，不适合新手同学学习，默认你已经具备的PHP编程基础，有一定的框架基础，学习起来更加容易。

二、实验步骤
------

*   设计模式简介
*   UML 类图
*   设计模式举例与实现

### 2.1 设计模式简介

开始实验之前，有必要先了解一些背景信息和相关基础知识。

> 在[软件工程](https://zh.wikipedia.org/wiki/%E8%BB%9F%E9%AB%94%E5%B7%A5%E7%A8%8B)中，**设计模式**（design pattern）是对[软件设计](https://zh.wikipedia.org/wiki/%E8%BB%9F%E4%BB%B6%E8%A8%AD%E8%A8%88)中普遍存在（反复出现）的各种问题，所提出的解决方案。
> 
> 设计模式并不直接用来完成[代码](https://zh.wikipedia.org/wiki/%E7%A8%8B%E5%BC%8F%E7%A2%BC)的编写，而是描述在各种不同情况下，要怎么解决问题的一种方案。[面向对象](https://zh.wikipedia.org/wiki/%E9%9D%A2%E5%90%91%E5%AF%B9%E8%B1%A1)设计模式通常以[类别](https://zh.wikipedia.org/wiki/%E9%A1%9E%E5%88%A5)或[对象](https://zh.wikipedia.org/wiki/%E7%89%A9%E4%BB%B6_(%E9%9B%BB%E8%85%A6%E7%A7%91%E5%AD%B8))来描述其中的关系和相互作用，但不涉及用来完成应用程序的特定类别或对象。设计模式能使不稳定依赖于相对稳定、具体依赖于相对抽象，避免会引起麻烦的紧耦合，以增强软件设计面对并适应变化的能力。
> 
> 《[设计模式](https://zh.wikipedia.org/wiki/%E8%AE%BE%E8%AE%A1%E8%8C%83%E4%BE%8B)》一书原先把设计模式分为创建型模式、结构型模式、行为型模式，把它们通过授权、聚合、诊断的概念来描述
> 
> ​ --参考维基百科

设计模式主要分为三大类，各自还有许多子类：

*   创建型模式

模式名

描述

抽象工厂模式

为一个产品族提供了统一的创建接口。当需要这个产品族的某一系列的时候，可以从抽象工厂中选出相应的系列创建一个具体的工厂类。

工厂方法模式

定义一个接口用于创建对象，但是让子类决定初始化哪个类。工厂方法把一个类的初始化下放到子类。

生成器模式

将一个复杂对象的构建与它的表示分离，使得同样的构建过程可以创建不同的表示。

惰性初始模式

推迟对象的创建、数据的计算等需要耗费较多资源的操作，只有在第一次访问的时候才执行。

对象池模式

通过回收利用对象避免获取和释放资源所需的昂贵成本。

原型模式

用原型实例指定创建对象的种类，并且通过拷贝这些原型创建新的对象。

单例模式

确保一个类只有一个实例，并提供对该实例的全局访问。

*   结构性模式

模式名

描述

适配器模式

将某个类的接口转换成客户端期望的另一个接口表示。适配器模式可以消除由于接口不匹配所造成的类兼容性问题。

桥接模式

将一个抽象与实现解耦，以便两者可以独立的变化。

组合模式

把多个对象组成树状结构来表示局部与整体，这样用户可以一样的对待单个对象和对象的组合。

修饰模式

向某个对象动态地添加更多的功能。修饰模式是除类继承外另一种扩展功能的方法。

外观模式

为子系统中的一组接口提供一个一致的界面， 外观模式定义了一个高层接口，这个接口使得这一子系统更加容易使用。

享元

通过共享以便有效的支持大量小颗粒对象。

代理

为其他对象提供一个代理以控制对这个对象的访问。

*   行为型模式

模式名

描述

黑板

广义的观察者在系统范围内交流信息，允许多位读者和写者。

责任链

为解除请求的发送者和接收者之间耦合，而使多个对象都有机会处理这个请求。将这些对象连成一条链，并沿着这条链传递该请求，直到有一个对象处理它。

命令

将一个请求封装为一个对象，从而使你可用不同的请求对客户进行参数化；对请求排队或记录请求日志，以及支持可取消的操作。

解释器

给定一个语言, 定义它的文法的一种表示，并定义一个解释器, 该解释器使用该表示来解释语言中的句子。

迭代器

提供一种方法顺序访问一个聚合对象中各个元素, 而又不需暴露该对象的内部表示。

中介者

包装了一系列对象相互作用的方式，使得这些对象不必相互明显作用，从而使它们可以松散偶合。当某些对象之间的作用发生改变时，不会立即影响其他的一些对象之间的作用，保证这些作用可以彼此独立的变化。

备忘录

备忘录对象是一个用来存储另外一个对象内部状态的快照的对象。备忘录模式的用意是在不破坏封装的条件下，将一个对象的状态捉住，并外部化，存储起来，从而可以在将来合适的时候把这个对象还原到存储起来的状态。

空对象

通过提供默认对象来避免空引用。

观察者模式

在对象间定义一个一对多的联系性，由此当一个对象改变了状态，所有其他相关的对象会被通知并且自动刷新。

规格

以布尔形式表示的可重绑定的商业逻辑。

状态

让一个对象在其内部状态改变的时候，其行为也随之改变。状态模式需要对每一个系统可能获取的状态创立一个状态类的子类。当系统的状态变化时，系统便改变所选的子类。

策略

定义一个算法的系列，将其各个分装，并且使他们有交互性。策略模式使得算法在用户使用的时候能独立的改变。

模板方法

模板方法模式准备一个抽象类，将部分逻辑以具体方法及具体构造子类的形式实现，然后声明一些抽象方法来迫使子类实现剩余的逻辑。不同的子类可以以不同的方式实现这些抽象方法，从而对剩余的逻辑有不同的实现。先构建一个顶级逻辑框架，而将逻辑的细节留给具体的子类去实现。

访问者

封装一些施加于某种数据结构元素之上的操作。一旦这些操作需要修改，接受这个操作的数据结构可以保持不变。访问者模式适用于数据结构相对未定的系统，它把数据结构和作用于结构上的操作之间的耦合解脱开，使得操作集合可以相对自由的演化。

当你看完上面这些介绍，可能你已经感受到了来自设计模式的压力，我也不例外，虽然我了解一些设计模式的知识，但是面对上面总结的各种模式，我也感到很无力，毕竟这是无数大牛精心设计且经过实践证明的''真理''。但是，越是这样的技术，越具有挑战性，你只要完全掌握上面内容的三分之一，你的编程水平已经上了一个台阶。了解并掌握设计模式的思想和原理，不仅有助于你写出优质健壮的代码，也将极大地提高系统的性能。同时你也将更容易的看懂他人优秀的代码。

Laravel 框架无疑是 PHP 中最优秀的框架之一，其优秀的原因在于他的先进的理念设计，优雅的代码结构，以及灵活的使用了大量的设计模式，使得框架非常稳健且易于扩展。所以，了解并掌握必要的设计模式的知识，是编程进阶的基础。

在本课程中，我将会根据相关资料参考，从三类设计模式挑选16个常用的设计模式来讲解，分为两个实验。

### 2.2 UML类图和时序图

如果你之前没有听说过或者接触过 UML ，那么可以在此处简单了解一下，更多详细的资料大家自行去查阅教程。

这里简单介绍一下UML类图和时序图的要点，让你可以看懂后续文档中给出的类图或时序图，可以更形象的帮助你理解设计模式。（UML内容较复杂，希望大家私下能去多了解一些相关知识）

首先，下面是一张典型的UML类图：

![此处输入图片的描述](https://doc.shiyanlou.com/document-uid108299labid2293timestamp1478843259466.png/wm)

> *   车的类图结构为<>，表示车是一个抽象类；
>     
> *   它有两个继承类：小汽车和自行车；它们之间的关系为实现关系，使用带实心箭头的虚线表示；
>     
> *   小汽车为与SUV之间也是继承关系，它们之间的关系为泛化关系，使用带空心箭头的实线表示；
>     
> *   小汽车与发动机之间是组合关系，使用带实心菱形的实线表示；
>     
> *   学生与班级之间是聚合关系，使用带空心菱形的实线表示；
>     
> *   学生与身份证之间为关联关系，使用一根实线表示；
>     
> *   学生上学需要用到自行车，与自行车是一种依赖关系，使用带箭头的虚线表示；
>     
>     --上述描述参考： [Graphic Design Patterns](https://design-patterns.readthedocs.io/zh_CN/latest/index.html)
>     

#### UML 类图与类的关系

部分内容参考：[UML类图与类的关系详解](http://www.uml.org.cn/oobject/201104212.asp)

向大家推荐一个在线UML类图制作工具：[processon](http://www.processon.com/)

类的关系有泛化(Generalization)、实现（Realization）、依赖(Dependency)和关联(Association)。其中关联又分为一般关联关系和聚合关系(Aggregation)，合成关系(Composition)

类图（Class Diagram）: 类图是面向对象系统建模中最常用和最重要的图，是定义其它图的基础。类图主要是用来显示系统中的类、接口以及它们之间的静态结构和关系的一种静态模型。

类图的3个基本组件：类名、属性、方法。

![此处输入图片的描述](https://doc.shiyanlou.com/document-uid108299labid2293timestamp1479198500927.png/wm)

#### 泛化(generalization)

表示is-a的关系，是对象之间耦合度最大的一种关系，子类继承父类的所有细节。直接使用语言中的继承表达。在类图中使用带三角空心箭头的实线表示，箭头从子类指向父类。

![此处输入图片的描述](https://doc.shiyanlou.com/document-uid108299labid2293timestamp1519615832951.png/wm)

#### 实现（Realization）

在类图中就是接口和实现的关系。在类图中使用带三角实心箭头的虚线表示，箭头从实现类指向接口。

![此处输入图片的描述](https://doc.shiyanlou.com/document-uid108299labid2293timestamp1479199007927.png/wm)

#### 关联关系(association)

关联关系是用一条带箭头的直线表示的；它描述不同类的对象之间的结构关系；它是一种静态关系， 通常与运行状态无关，一般由常识等因素决定的；它一般用来定义对象之间静态的、天然的结构； 所以，关联关系是一种“强关联”的关系；

学生与学校是一种关联关系。

![此处输入图片的描述](https://doc.shiyanlou.com/document-uid108299labid2293timestamp1479199479813.png/wm)

#### 依赖(Dependency)

依赖关系是用一套带箭头的虚线表示的；如下图表示A依赖于B；他描述一个对象在运行期间会用到另一个对象的关系；

对象之间最弱的一种关联方式，是临时性的关联。代码中一般指由局部变量、函数参数、返回值建立的对于其他对象的调用关系。一个类调用被依赖类中的某些方法而得以完成这个类的一些职责。在类图使用带箭头的虚线表示，箭头从使用类指向被依赖的类。

![此处输入图片的描述](https://doc.shiyanlou.com/document-uid108299labid2293timestamp1479199678874.png/wm)

#### 聚合(Aggregation)

表示has-a的关系，是一种不稳定的包含关系。较强于一般关联,有整体与局部的关系,并且没有了整体,局部也可单独存在。如公司和员工的关系，公司包含员工，但如果公司倒闭，员工依然可以换公司。在类图使用空心的菱形表示，菱形从局部指向整体。

![此处输入图片的描述](https://doc.shiyanlou.com/document-uid108299labid2293timestamp1479199877080.png/wm)

#### 组合(Composition)

表示contains-a的关系，是一种强烈的包含关系。组合类负责被组合类的生命周期。是一种更强的聚合关系。部分不能脱离整体存在。如公司和部门的关系，没有了公司，部门也不能存在了；调查问卷中问题和选项的关系；订单和订单选项的关系。在类图使用实心的菱形表示，菱形从局部指向整体。

![此处输入图片的描述](https://doc.shiyanlou.com/document-uid108299labid2293timestamp1479199980657.png/wm)

#### 聚合和组合的区别

这两个比较难理解，重点说一下。聚合和组合的区别在于：聚合关系是“has-a”关系，组合关系是“contains-a”关系；聚合关系表示整体与部分的关系比较弱，而组合比较强；聚合关系中代表部分事物的对象与代表聚合事物的对象的生存期无关，一旦删除了聚合对象不一定就删除了代表部分事物的对象。组合中一旦删除了组合对象，同时也就删除了代表部分事物的对象。

此外，还有 UML 时序图，这部分就留给大家自行去了解学习，此处不做介绍。

### 2.3 设计模式详解（1-8）

#### 工厂模式

工厂模式具体可分为三类模式：简单工厂模式，工厂方法模式，抽象工厂模式；

1.**简单工厂模式**

又称为静态工厂方法(Static Factory Method)模式，它属于类创建型模式。在简单工厂模式中，可以根据参数的不同返回不同类的实例。简单工厂模式专门定义一个类来负责创建其他类的实例，被创建的实例通常都具有共同的父类。

`角色：`

Factory类：负责创建具体产品的实例

Product类：抽象产品类，定义产品子类的公共接口

ConcreteProduct 类：具体产品类，实现Product父类的接口功能，也可添加自定义的功能

`UML类图：`

![此处输入图片的描述](https://doc.shiyanlou.com/document-uid108299labid2293timestamp1479202997019.png/wm)

`示例代码：`:`Factory.class.php`

      <?php 
      //简单工厂模式
      class Cat
      {
          function __construct()
          {
              echo "I am Cat class <br>";
          }
      }
      class Dog
      {
          function __construct()
          {
              echo "I am Dog class <br>";
          }
      }
      class Factory
      {
          public static function CreateAnimal($name){
              if ($name == 'cat') {
                  return new Cat();
              } elseif ($name == 'dog') {
                  return new Dog();
              }
          }
      }
    
      $cat = Factory::CreateAnimal('cat');
      $dog = Factory::CreateAnimal('dog');
    

简单工厂模式最大的优点在于实现对象的创建和对象的使用分离，将对象的创建交给专门的工厂类负责，但是其最大的缺点在于工厂类不够灵活，增加新的具体产品需要修改工厂类的判断逻辑代码，而且产品较多时，工厂方法代码将会非常复杂。

* * *

2.**工厂方法模式**

此模式中，通过定义一个抽象的核心工厂类，并定义创建产品对象的接口，创建具体产品实例的工作延迟到其工厂子类去完成。这样做的好处是核心类只关注工厂类的接口定义，而具体的产品实例交给具体的工厂子类去创建。当系统需要新增一个产品，无需修改现有系统代码，只需要添加一个具体产品类和其对应的工厂子类，是系统的扩展性变得很好，符合面向对象编程的`开闭原则`;

`角色：`

Product：抽象产品类

ConcreteProduct：具体产品类

Factory：抽象工厂类

ConcreteFactory：具体工厂类

`UML类图：`

![此处输入图片的描述](https://doc.shiyanlou.com/document-uid108299labid2297timestamp1486374011050.png/wm)

`示例代码：`:`ConcreteFactory.class.php`

      <?php 
      interface Animal{
          public function run();
          public function say();
      }
      class Cat implements Animal
      {
          public function run(){
              echo "I ran slowly <br>";
          }
          public function say(){
              echo "I am Cat class <br>";
          }
      }
      class Dog implements Animal
      {
          public function run(){
              echo "I'm running fast <br>";
          }
          public function say(){
              echo "I am Dog class <br>";
          }
      }
      abstract class Factory{
          abstract static function createAnimal();
      }
      class CatFactory extends Factory
      {
          public static function createAnimal()
          {
              return new Cat();
          }
      }
      class DogFactory extends Factory
      {
          public static function createAnimal()
          {
              return new Dog();
          }
      }
    
      $cat = CatFactory::createAnimal();
      $cat->say();
      $cat->run();
    
      $dog = DogFactory::createAnimal();
      $dog->say();
      $dog->run();
    

工厂方法模式是简单工厂模式的进一步抽象和推广。由于使用了面向对象的多态性，工厂方法模式保持了简单工厂模式的优点，而且克服了它的缺点。在工厂方法模式中，核心的工厂类不再负责所有产品的创建，而是将具体创建工作交给子类去做。这个核心类仅仅负责给出具体工厂必须实现的接口，而不负责产品类被实例化这种细节，这使得工厂方法模式可以允许系统在不修改工厂角色的情况下引进新产品。

* * *

3.**抽象工厂模式**

提供一个创建一系列相关或相互依赖对象的接口，而无须指定它们具体的类。抽象工厂模式又称为Kit模式，属于对象创建型模式。

此模式是对工厂方法模式的进一步扩展。在工厂方法模式中，一个具体的工厂负责生产一类具体的产品，即一对一的关系，但是，如果需要一个具体的工厂生产多种产品对象，那么就需要用到抽象工厂模式了。

为了便于理解此模式，这里介绍两个概念：

*   **产品等级结构**：产品等级结构即产品的继承结构，如一个抽象类是电视机，其子类有海尔电视机、海信电视机、TCL电视机，则抽象电视机与具体品牌的电视机之间构成了一个产品等级结构，抽象电视机是父类，而具体品牌的电视机是其子类。
*   **产品族 ：**在抽象工厂模式中，产品族是指由同一个工厂生产的，位于不同产品等级结构中的一组产品，如海尔电器工厂生产的海尔电视机、海尔电冰箱，海尔电视机位于电视机产品等级结构中，海尔电冰箱位于电冰箱产品等级结构中。
    
    `角色：`
    
    抽象工厂（AbstractFactory）：担任这个角色的是抽象工厂模式的核心，是与应用系统的商业逻辑无关的。
    
    具体工厂（Factory）：这个角色直接在客户端的调用下创建产品的实例，这个角色含有选择合适的产品对象的逻辑，而这个逻辑是与应用系统商业逻辑紧密相关的。
    
    抽象产品（AbstractProduct）：担任这个角色的类是抽象工厂模式所创建的对象的父类，或它们共同拥有的接口
    
    具体产品（Product）：抽象工厂模式所创建的任何产品对象都是一个具体的产品类的实例。
    
    `UML类图：`
    
    ![此处输入图片的描述](https://doc.shiyanlou.com/document-uid108299labid2293timestamp1479204958020.png/wm)
    
    `示例代码：`:`AbstructFactory.class.php`
    
        <?php 
        
        interface TV{
          public function open();
          public function watch();
        }
        
        class HaierTv implements TV
        {
          public function open()
          {
              echo "Open Haier TV <br>";
          }
        
          public function watch()
          {
              echo "I'm watching TV <br>";
          }
        }
        
        interface PC{
          public function work();
          public function play();
        }
        
        class LenovoPc implements PC
        {
          public function work()
          {
              echo "I'm working on a Lenovo computer <br>";
          }
          public function play()
          {
              echo "Lenovo computers can be used to play games <br>";
          }
        }
        
        abstract class Factory{
          abstract public static function createPc();
          abstract public static function createTv();
        }
        
        class ProductFactory extends Factory
        {
          public static function createTV()
          {
              return new HaierTv();
          }
          public static function createPc()
          {
              return new LenovoPc();
          }
        }
        
        $newTv = ProductFactory::createTV();
        $newTv->open();
        $newTv->watch();
        
        $newPc = ProductFactory::createPc();
        $newPc->work();
        $newPc->play();
        
    

#### 建造者模式

又名：生成器模式，是一种对象构建模式。它可以将复杂对象的建造过程抽象出来（抽象类别），使这个抽象过程的不同实现方法可以构造出不同表现（属性）的对象。

建造者模式是一步一步创建一个复杂的对象，它允许用户只通过指定复杂对象的类型和内容就可以构建它们，用户不需要知道内部的具体构建细节。例如，一辆汽车由轮子，发动机以及其他零件组成，对于普通人而言，我们使用的只是一辆完整的车，这时，我们需要加入一个构造者，让他帮我们把这些组件按序组装成为一辆完整的车。

`角色：`

Builder：抽象构造者类，为创建一个Product对象的各个部件指定抽象接口。

ConcreteBuilder：具体构造者类，实现Builder的接口以构造和装配该产品的各个部件。定义并明确它所创建的表示。提供一个检索产品的接口

Director：指挥者，构造一个使用Builder接口的对象。

Product：表示被构造的复杂对象。ConcreateBuilder创建该产品的内部表示并定义它的装配过程。

包含定义组成部件的类，包括将这些部件装配成最终产品的接口。

`UML类图：`

![此处输入图片的描述](https://doc.shiyanlou.com/document-uid108299labid2297timestamp1486373749271.png/wm)

`示例代码：`:`Builder.class.php`

      <?php 
      /**
      * chouxiang builer
      */
      abstract class Builder
      {
          protected $car;
          abstract public function buildPartA();
          abstract public function buildPartB();
          abstract public function buildPartC();
          abstract public function getResult();
      }
    
      class CarBuilder extends Builder
      {
          function __construct()
          {
              $this->car = new Car();
          }
          public function buildPartA(){
              $this->car->setPartA('发动机');
          }
    
          public function buildPartB(){
              $this->car->setPartB('轮子');
          }
    
          public function buildPartC(){
              $this->car->setPartC('其他零件');
          }
    
          public function getResult(){
              return $this->car;
          }
      }
    
      class Car
      {
          protected $partA;
          protected $partB;
          protected $partC;
    
          public function setPartA($str){
              $this->partA = $str;
          }
    
          public function setPartB($str){
              $this->partB = $str;
          }
    
          public function setPartC($str){
              $this->partC = $str;
          }
    
          public function show()
          {
              echo "这辆车由：".$this->partA.','.$this->partB.',和'.$this->partC.'组成';
          }
      }
    
      class Director
      {
          public $myBuilder;
    
          public function startBuild()
          {
              $this->myBuilder->buildPartA();
              $this->myBuilder->buildPartB();
              $this->myBuilder->buildPartC();
              return $this->myBuilder->getResult();
          }
    
          public function setBuilder(Builder $builder)
          {
              $this->myBuilder = $builder;
          }
      }
    
      $carBuilder = new CarBuilder();
      $director = new Director();
      $director->setBuilder($carBuilder);
      $newCar = $director->startBuild();
      $newCar->show();
    

#### 单例模式

> **单例模式**，也叫**单子模式**，是一种常用的[软件设计模式](https://zh.wikipedia.org/wiki/%E8%BD%AF%E4%BB%B6%E8%AE%BE%E8%AE%A1%E6%A8%A1%E5%BC%8F)。在应用这个模式时，单例对象的[类](https://zh.wikipedia.org/wiki/%E7%B1%BB)必须保证只有一个实例存在。许多时候整个系统只需要拥有一个的全局[对象](https://zh.wikipedia.org/wiki/%E5%AF%B9%E8%B1%A1)，这样有利于我们协调系统整体的行为。
> 
> 实现单例模式的思路是：一个类能返回对象一个引用(永远是同一个)和一个获得该实例的方法（必须是静态方法，通常使用getInstance这个名称）；当我们调用这个方法时，如果类持有的引用不为空就返回这个引用，如果类保持的引用为空就创建该类的实例并将实例的引用赋予该类保持的引用；同时我们还将该类的[构造函数](https://zh.wikipedia.org/wiki/%E6%9E%84%E9%80%A0%E5%87%BD%E6%95%B0)定义为私有方法，这样其他处的代码就无法通过调用该类的构造函数来实例化该类的对象，只有通过该类提供的静态方法来得到该类的唯一实例。
> 
> ---维基百科

单例模式的要点有：某个类只能有一个实例；它必须自行创建本身的实例；它必须自行向整个系统提供这个实例。单例模式是一种对象创建型模式。

`角色：`

Singleton：单例类

`UML 类图：`

![此处输入图片的描述](https://doc.shiyanlou.com/document-uid108299labid2297timestamp1486368498821.png/wm)

``示例代码` ``Singleton.class.php`

      <?php 
    
      class Singleton
      {
          private static $instance;
          //私有构造方法，禁止使用new创建对象
          private function __construct(){}
    
          public static function getInstance(){
              if (!isset(self::$instance)) {
                  self::$instance = new self;
              }
              return self::$instance;
          }
          //将克隆方法设为私有，禁止克隆对象
          private function __clone(){}
    
          public function say()
          {
              echo "这是用单例模式创建对象实例 <br>";
          }
          public function operation()
          {
              echo "这里可以添加其他方法和操作 <br>";
          }
      }
    
      // $shiyanlou = new Singleton();
      $shiyanlou = Singleton::getInstance();
      $shiyanlou->say();
      $shiyanlou->operation();
    
      $newShiyanlou = Singleton::getInstance();
      var_dump($shiyanlou === $newShiyanlou);
    

* * *

上述的几个模式均属于`创建型模式`，接下来将要介绍的模式属于结构型模式，在本实验后面的文档将介绍三个，剩下来的留在下一个实验继续介绍。

#### 适配器模式

> 在[设计模式](https://zh.wikipedia.org/wiki/%E8%AE%BE%E8%AE%A1%E6%A8%A1%E5%BC%8F_(%E8%AE%A1%E7%AE%97%E6%9C%BA))中，**适配器模式**（英语：adapter pattern）有时候也称包装样式或者包装(wrapper)。将一个[类](https://zh.wikipedia.org/wiki/%E7%B1%BB_(%E8%AE%A1%E7%AE%97%E6%9C%BA%E7%A7%91%E5%AD%A6))的接口转接成用户所期待的。一个适配使得因接口不兼容而不能在一起工作的类工作在一起，做法是将类自己的接口包裹在一个已存在的类中。
> 
> ---维基百科

顾名思义，此模式是源于类似于电源适配器的设计和编码技巧。比如现在有一些类，提供一些可用的接口，但是可能客户端因为不兼容的原因，不能直接调用这些现有的接口，这时就需要一个适配器来作为中转站，适配器类可以向用户提供可用的接口，其内部将收到的请求转换为对适配者对应接口的真是请求，从而实现对不兼容的类的复用。

优点：将目标类和适配者类解耦，通过引入一个适配器类来重用现有的适配者类，而无须修改原有代码。增加了类的透明性和复用性，将具体的实现封装在适配者类中，对于客户端类来说是透明的，而且提高了适配者的复用性。

`角色：`

Target：目标抽象类

Adapter：适配器类

Adaptee：适配者类

Client：客户类

`UML 类图:`

![此处输入图片的描述](https://doc.shiyanlou.com/document-uid108299labid2297timestamp1486370324222.png/wm)

`示例代码:`:`Adapter.class.php`

      <?php 
    
      class Adaptee
      {
          public function realRequest()
          {
              echo "这是被适配者真正的调用方法";
          }
      }
    
      interface Target{
          public function request();
      }
    
      class Adapter implements Target
      {
          protected $adaptee;
          function __construct(Adaptee $adaptee)
          {
              $this->adaptee = $adaptee;
          }
    
          public function request()
          {
              echo "适配器转换：";
              $this->adaptee->realRequest();
          }
      }
    
      $adaptee = new Adaptee();
      $target = new Adapter($adaptee);
      $target->request();
    

#### 桥接模式

桥接模式是[软件设计模式](https://zh.wikipedia.org/wiki/%E8%BB%9F%E4%BB%B6%E8%A8%AD%E8%A8%88%E6%A8%A1%E5%BC%8F)中最复杂的模式之一，它把事物对象和其具体行为、具体特征分离开来，使它们可以各自独立的变化。事物对象仅是一个抽象的概念。如“圆形”、“三角形”归于抽象的“形状”之下，而“画圆”、“画三角”归于实现行为的“画图”类之下，然后由“形状”调用“画图”。

理解桥接模式，重点需要理解如何将抽象化(Abstraction)与实现化(Implementation)脱耦，使得二者可以独立地变化。桥接模式提高了系统的可扩充性，在两个变化维度中任意扩展一个维度，都不需要修改原有系统。

`角色：`

Abstraction：定义抽象的接口，该接口包含实现具体行为、具体特征的Implementor接口

Refined Abstraction：抽象接口Abstraction的子类，依旧是一个抽象的事物名

Implementor：定义具体行为、具体特征的应用接口

ConcreteImplementor：实现Implementor接口

`UML类图`

![此处输入图片的描述](https://doc.shiyanlou.com/document-uid108299labid2297timestamp1486371373063.png/wm)

`示例代码` `DrawingAPI.class.php`

      <?php 
      interface DrawingAPI{
          public function drawCircle($x,$y,$radius);
      }
    
      /**
      * drawAPI1
      */
      class DrawingAPI1 implements DrawingAPI
      {
          public function drawCircle($x,$y,$radius)
          {
              echo "API1.circle at (".$x.','.$y.') radius '.$radius.'<br>';
          }
      }
    
      /**
      * drawAPI2
      */
      class DrawingAPI2 implements DrawingAPI
      {
          public function drawCircle($x,$y,$radius)
          {
              echo "API2.circle at (".$x.','.$y.') radius '.$radius.'<br>';
          }
      }
    
      /**
      *shape接口
      */
      interface Shape{
          public function draw();
          public function resize($radius);
      }
    
      class CircleShape implements Shape
      {
          private $x;
          private $y;
          private $radius;
          private $drawingAPI;
          function __construct($x,$y,$radius,DrawingAPI $drawingAPI)
          {
              $this->x = $x;
              $this->y = $y;
              $this->radius = $radius;
              $this->drawingAPI = $drawingAPI;
          }
    
          public function draw()
          {
              $this->drawingAPI->drawCircle($this->x,$this->y,$this->radius);
          }
    
          public function resize($radius)
          {
              $this->radius = $radius;
          }
      }
    
      $shape1 = new CircleShape(1,2,4,new DrawingAPI1());
      $shape2 = new CircleShape(1,2,4,new DrawingAPI2());
      $shape1->draw();
      $shape2->draw();
      $shape1->resize(10);
      $shape1->draw();
    

* * *

#### 装饰器模式

**修饰模式**，是[面向对象编程](https://zh.wikipedia.org/wiki/%E9%9D%A2%E5%90%91%E5%AF%B9%E8%B1%A1%E7%BC%96%E7%A8%8B)领域中，一种动态地往一个类中添加新的行为的[设计模式](https://zh.wikipedia.org/wiki/%E8%BD%AF%E4%BB%B6%E8%AE%BE%E8%AE%A1%E6%A8%A1%E5%BC%8F)。就功能而言，修饰模式相比生成[子类](https://zh.wikipedia.org/wiki/%E5%AD%90%E7%B1%BB)更为灵活，这样可以给某个对象而不是整个类添加一些功能。

一般来说，给一个对象或者类增加行为的方式可以有两种：

*   继承机制，使用继承机制是给现有类添加功能的一种有效途径，通过继承一个现有类可以使得子类在拥有自身方法的同时还拥有父类的方法。但是这种方法是静态的，用户不能控制增加行为的方式和时机。
*   关联机制，即将一个类的对象嵌入另一个对象中，由另一个对象来决定是否调用嵌入对象的行为以便扩展自己的行为，我们称这个嵌入的对象为装饰器(Decorator)
    
    通过使用修饰模式，可以在运行时扩充一个类的功能。原理是：增加一个修饰类包裹原来的类，包裹的方式一般是通过在将原来的对象作为修饰类的构造函数的参数。装饰类实现新的功能，但是，在不需要用到新功能的地方，它可以直接调用原来的类中的方法。修饰类必须和原来的类有相同的接口。
    
    修饰模式是类继承的另外一种选择。类继承在编译时候增加行为，而装饰模式是在运行时增加行为。
    
    `角色`
    
    Component: 抽象构件
    
    ConcreteComponent: 具体构件
    
    Decorator: 抽象装饰类
    
    ConcreteDecorator: 具体装饰类
    
    `UML 类图`
    
    ![此处输入图片的描述](https://doc.shiyanlou.com/document-uid108299labid2293timestamp1479221663191.png/wm)
    
    `示例代码`：`Component.class.php`
    
        <?php 
        abstract class Component {
          abstract public function operation();
        }
        
        class MyComponent extends Component
        {
          public function operation()
          {
              echo "这是正常的组件方法 <br>";
          }
        }
        
        abstract class Decorator extends Component {
          protected $component;
          function __construct(Component $component)
          {
              $this->component = $component;
          }
        
          public function operation()
          {
              $this->component->operation();
          }
        }
        
        class MyDecorator extends Decorator
        {
        
          function __construct(Component $component)
          {
              parent::__construct($component);
          }
        
          public function addMethod()
          {
              echo "这是装饰器添加的方法 <br>";
          }
        
          public function operation()
          {
              $this->addMethod();
              parent::operation();
          }
        }
        
        $component = new MyComponent();
        $da = new MyDecorator($component);
        $da->operation();
        
    

\[{"name":"检查是否存在文件","script":"#!/bin/bash\\ngrep Component /home/shiyanlou/Component.class.php\\n","error":"我们发现您还没有完成程序 /home/shiyanlou/Component.class.php\\n"}\]

三、实验总结
------

本次实验内容较多，首先介绍了设计模式的相关知识，让大家了解了常用的设计模式有哪些分类和具体模式。随后向大家简单介绍了 UML 类图的相关知识点，让大家可以看懂简单的UML类图，更加形象的理解设计中各个类之间的关系，当然，更多详细的内容还需自行去了解。

接下来就是向大家介绍了八种具体设计模式，包括五种创建型模式：工厂模式（简单工厂模式。工厂方法模式，抽象工厂模式），建造者模式，单例模式以及三种结构型模式：适配器模式，桥接模式，装饰器模式。

上面每个设计模式都附有一个实现的demo，代码结构并不复杂，非常适合用来学习理解。希望大家能用心花时间来理解。下个实验继续！