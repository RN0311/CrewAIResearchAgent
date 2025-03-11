import os
from crewai import Agent, Task, Crew, Process
from langchain.chat_models import ChatOpenAI
from langchain_community.tools import DuckDuckGoSearchRun

import os
import time

from langchain_community.tools import DuckDuckGoSearchRun
from typing import Optional
from langchain.callbacks.manager import CallbackManagerForToolRun

os.environ["OPENAI_API_KEY"] = "" #YOUR API KEY HERE

llm = ChatOpenAI(model="gpt-4", temperature=0.7) #CHANGE MODEL TYPE IF NEEDED

search_tool = DuckDuckGoSearchRun()

class LimitedDuckDuckGoSearchRun(DuckDuckGoSearchRun):
    def _run(
        self,
        query: str,
        run_manager: Optional[CallbackManagerForToolRun] = None,
    ) -> str:
        try:
            time.sleep(3)
            return self.api_wrapper.run(query)
        except Exception as e:
            return f"🔍 Search could not be completed due to rate limits. Using existing knowledge instead. Error: {str(e)}"


llm = ChatOpenAI(model="gpt-4", temperature=0.7)
search_tool = LimitedDuckDuckGoSearchRun()

research_agent = Agent(
    role="📚 Research Specialist",
    goal="Identify key papers in the research area using knowledge and limited searches",
    backstory="""You are an expert researcher with deep knowledge of recent academic literature.
    You use a combination of your knowledge and careful searching to find important papers.
    You prefer quality over quantity and focus on truly influential work. 
    When searches fail, you rely on your extensive knowledge of the field.""",
    verbose=True,
    allow_delegation=False,
    tools=[search_tool],
    llm=llm
)

analysis_agent = Agent(
    role="🔍 Data Analyst",
    goal="Analyze methodologies and findings from research papers",
    backstory="""You are skilled at identifying patterns and extracting key findings
    from academic research. You understand various methodological approaches and
    can clearly explain complex technical concepts in accessible language.""",
    verbose=True,
    allow_delegation=False,
    llm=llm
)

critic_agent = Agent(
    role="⚖️ Research Critic",
    goal="Evaluate limitations and biases in research methodologies",
    backstory="""You excel at identifying methodological weaknesses, biases,
    and gaps in research. You understand what makes research robust and are
    not afraid to point out limitations while remaining constructive.""",
    verbose=True,
    allow_delegation=False,
    llm=llm
)

synthesis_agent = Agent(
    role="🧩 Research Synthesizer",
    goal="Combine insights from multiple sources into a coherent narrative",
    backstory="""You are skilled at creating coherent narratives that connect
    different research findings, highlighting areas of consensus and debate.
    You can see the big picture across diverse research approaches.""",
    verbose=True,
    allow_delegation=False,
    llm=llm
)

recommendation_agent = Agent(
    role="💡 Applications Specialist",
    goal="Suggest practical applications of research findings",
    backstory="""You translate academic knowledge into practical applications,
    identifying industries and contexts where research can be applied.
    You bridge the gap between theory and practice with creative yet realistic ideas.""",
    verbose=True,
    allow_delegation=False,
    llm=llm
)

def analyze_research_topic(topic):
    print(f"🚀 Starting analysis on: {topic}")
    
    research_task = Task(
        description=f"""
        🔎 Research Task:
        
        Find 2-4 important papers on {topic} from recent years. Use one focused search if needed,
        but rely on your knowledge if search fails.
        
        For each paper, provide:
        1. 📝 Estimated title and authors (based on your knowledge or search)
        2. 📅 Approximate publication year
        3. 💫 Key findings and contributions
        4. 🔬 Methodological approach
        
        Format your response with clear headers and emojis for readability.
        Quality is more important than quantity - focus on truly significant papers.
        """,
        agent=research_agent,
        expected_output="A summary of important papers with emojis for organization",
    )

    analysis_task = Task(
        description=f"""
        📊 Analysis Task:
        
        Based on the research summary for {topic}, analyze:
        
        1. 🧪 Methodological approaches - what techniques are researchers using?
        2. 🔑 Key findings - what are the most important discoveries?
        3. 📈 Trends - how is this research area evolving?
        4. 🔄 Common patterns across different papers
        
        Use emojis and clear formatting to make your analysis easy to understand.
        """,
        agent=analysis_agent,
        expected_output="An analysis of research approaches and findings with emoji organization",
        context=[research_task]
    )

    critique_task = Task(
        description=f"""
        🔍 Critique Task:
        
        Critically evaluate the research on {topic}:
        
        1. ⚠️ Limitations - what weaknesses exist in current approaches?
        2. 🧿 Biases - what perspectives or data might be missing?
        3. 🔮 Gaps - what important questions remain unexplored?
        4. 🔄 Contradictions - where do researchers disagree?
        
        Be constructive but honest in your assessment.
        Use emojis and clear formatting for readability.
        """,
        agent=critic_agent,
        expected_output="A critical evaluation with emoji-highlighted points",
        context=[research_task, analysis_task]
    )

    synthesis_task = Task(
        description=f"""
        🧩 Synthesis Task:
        
        Create a coherent narrative about {topic}:
        
        1. 🌐 Overview - what is the current state of knowledge?
        2. 🤝 Consensus - what do researchers agree on?
        3. 💬 Debates - what questions are still being discussed?
        4. 🚀 Evolution - how has this field developed recently?
        
        Connect the research, analysis, and critique into a unified story.
        Use emojis and clear formatting to enhance readability.
        """,
        agent=synthesis_agent,
        expected_output="A synthesis narrative with emoji section markers",
        context=[research_task, analysis_task, critique_task]
    )

    recommendation_task = Task(
        description=f"""
        💡 Recommendations Task:
        
        Suggest practical applications for {topic}:
        
        1. 🏢 Industries that could benefit
        2. 🛠️ Potential products or services
        # 3. 🚀 Implementation strategies
        # 4. 🔮 Future opportunities
        
        Be specific and creative while remaining realistic.
        Use emojis and clear formatting for each recommendation.
        """,
        agent=recommendation_agent,
        expected_output="Practical application recommendations with emojis",
        context=[synthesis_task]
    )

    research_crew = Crew(
        agents=[research_agent, analysis_agent, critic_agent, synthesis_agent, recommendation_agent],
        tasks=[research_task, analysis_task, critique_task, synthesis_task, recommendation_task],
        verbose=True,
        process=Process.sequential
    )
    
    try:
        result = research_crew.kickoff()
        return result
    except Exception as e:
        print(f"❌ An error occurred: {str(e)}")
        return f"❌ Research process could not be completed. Error: {str(e)}"

if __name__ == "__main__":
    research_topic = "transformer models for medical image analysis"
    results = analyze_research_topic(research_topic)
    print("\n\n🎉 FINAL RESEARCH ANALYSIS RESULTS:")
    print(results)
